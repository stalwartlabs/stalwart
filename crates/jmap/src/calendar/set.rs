/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::api::acl::{JmapAcl, JmapRights};
use common::{Server, auth::AccessToken, sharing::EffectiveAcl};
use groupware::{DestroyArchive, cache::GroupwareCache};
use http_proto::HttpSessionData;
use jmap_proto::{
    error::set::SetError,
    method::set::{SetRequest, SetResponse},
    object::calendar::{self, CalendarProperty, CalendarValue},
    request::IntoValid,
    types::state::State,
};
use jmap_tools::{JsonPointerItem, Key, Value};
use rand::{Rng, distr::Alphanumeric};
use store::write::BatchBuilder;
use trc::AddContext;
use types::{
    acl::{Acl, AclGrant},
    collection::{Collection, SyncCollection},
};

pub trait CalendarSet: Sync + Send {
    fn calendar_set(
        &self,
        request: SetRequest<'_, calendar::Calendar>,
        access_token: &AccessToken,
        session: &HttpSessionData,
    ) -> impl Future<Output = trc::Result<SetResponse<calendar::Calendar>>> + Send;
}

impl CalendarSet for Server {
    async fn calendar_set(
        &self,
        mut request: SetRequest<'_, calendar::Calendar>,
        access_token: &AccessToken,
        _session: &HttpSessionData,
    ) -> trc::Result<SetResponse<calendar::Calendar>> {
        todo!()
        /*let account_id = request.account_id.document_id();
        let cache = self
            .fetch_dav_resources(access_token, account_id, SyncCollection::Calendar)
            .await?;
        let mut response = SetResponse::from_request(&request, self.core.jmap.set_max_objects)?;
        let will_destroy = request.unwrap_destroy().into_valid().collect::<Vec<_>>();
        let is_shared = access_token.is_shared(account_id);

        let todo = " Implement onSuccessSetIsDefault + Sieve";

        // Process creates
        let mut batch = BatchBuilder::new();
        'create: for (id, object) in request.unwrap_create() {
            if is_shared {
                response.not_created.append(
                    id,
                    SetError::forbidden()
                        .with_description("Cannot create calendars in a shared account."),
                );
                continue 'create;
            }

            let mut calendar = Calendar {
                name: rand::rng()
                    .sample_iter(Alphanumeric)
                    .take(10)
                    .map(char::from)
                    .collect::<String>(),
                preferences: vec![CalendarPreferences {
                    account_id,
                    name: "Address Book".to_string(),
                    ..Default::default()
                }],
                ..Default::default()
            };

            // Process changes
            if let Err(err) = update_calendar(object, &mut calendar, access_token) {
                response.not_created.append(id, err);
                continue 'create;
            }

            // Validate ACLs
            if !calendar.acls.is_empty() {
                if let Err(err) = self.acl_validate(&calendar.acls).await {
                    response.not_created.append(id, err.into());
                    continue 'create;
                }

                self.refresh_acls(&calendar.acls, None).await;
            }

            // Insert record
            let document_id = self
                .store()
                .assign_document_ids(account_id, Collection::Calendar, 1)
                .await
                .caused_by(trc::location!())?;
            calendar
                .insert(access_token, account_id, document_id, &mut batch)
                .caused_by(trc::location!())?;
            response.created(id, document_id);
        }

        // Process updates
        'update: for (id, object) in request.unwrap_update().into_valid() {
            // Make sure id won't be destroyed
            if will_destroy.contains(&id) {
                response.not_updated.append(id, SetError::will_destroy());
                continue 'update;
            }

            // Obtain calendar
            let document_id = id.document_id();
            let calendar_ = if let Some(calendar_) = self
                .get_archive(account_id, Collection::Calendar, document_id)
                .await?
            {
                calendar_
            } else {
                response.not_updated.append(id, SetError::not_found());
                continue 'update;
            };
            let calendar = calendar_
                .to_unarchived::<Calendar>()
                .caused_by(trc::location!())?;
            let mut new_calendar = calendar
                .deserialize::<Calendar>()
                .caused_by(trc::location!())?;

            // Apply changes
            let has_acl_changes = match update_calendar(object, &mut new_calendar, access_token) {
                Ok(has_acl_changes_) => has_acl_changes_,
                Err(err) => {
                    response.not_updated.append(id, err);
                    continue 'update;
                }
            };

            // Validate ACL
            if is_shared {
                let acl = calendar.inner.acls.effective_acl(access_token);
                if !acl.contains(Acl::Modify) || (has_acl_changes && !acl.contains(Acl::Administer))
                {
                    response.not_updated.append(
                        id,
                        SetError::forbidden()
                            .with_description("You are not allowed to modify this calendar."),
                    );
                    continue 'update;
                }
            }
            if has_acl_changes {
                if let Err(err) = self.acl_validate(&new_calendar.acls).await {
                    response.not_updated.append(id, err.into());
                    continue 'update;
                }
                self.refresh_acls(
                    &new_calendar.acls,
                    Some(
                        calendar
                            .inner
                            .acls
                            .iter()
                            .map(AclGrant::from)
                            .collect::<Vec<_>>()
                            .as_slice(),
                    ),
                )
                .await;
            }

            // Update record
            new_calendar
                .update(access_token, calendar, account_id, document_id, &mut batch)
                .caused_by(trc::location!())?;
            response.updated.append(id, None);
        }

        // Process deletions
        let on_destroy_remove_contents = request
            .arguments
            .on_destroy_remove_contents
            .unwrap_or(false);
        for id in will_destroy {
            let document_id = id.document_id();

            if !cache.has_container_id(&document_id) {
                response.not_destroyed.append(id, SetError::not_found());
                continue;
            };

            let Some(calendar_) = self
                .get_archive(account_id, Collection::Calendar, document_id)
                .await
                .caused_by(trc::location!())?
            else {
                response.not_destroyed.append(id, SetError::not_found());
                continue;
            };

            let calendar = calendar_
                .to_unarchived::<Calendar>()
                .caused_by(trc::location!())?;

            // Validate ACLs
            if is_shared
                && !calendar
                    .inner
                    .acls
                    .effective_acl(access_token)
                    .contains_all([Acl::Delete, Acl::RemoveItems].into_iter())
            {
                response.not_destroyed.append(
                    id,
                    SetError::forbidden()
                        .with_description("You are not allowed to delete this calendar."),
                );
                continue;
            }

            // Obtain children ids
            let children_ids = cache.children_ids(document_id).collect::<Vec<_>>();
            if !children_ids.is_empty() && !on_destroy_remove_contents {
                response
                    .not_destroyed
                    .append(id, SetError::calendar_has_contents());
                continue;
            }

            // Delete record
            DestroyArchive(calendar)
                .delete_with_cards(
                    self,
                    access_token,
                    account_id,
                    document_id,
                    children_ids,
                    None,
                    &mut batch,
                )
                .await
                .caused_by(trc::location!())?;

            response.destroyed.push(id);
        }

        // Write changes
        if !batch.is_empty() {
            let change_id = self
                .commit_batch(batch)
                .await
                .and_then(|ids| ids.last_change_id(account_id))
                .caused_by(trc::location!())?;

            response.new_state = State::Exact(change_id).into();
        }

        Ok(response)*/
    }
}

/*fn update_calendar(
    updates: Value<'_, CalendarProperty, CalendarValue>,
    calendar: &mut Calendar,
    access_token: &AccessToken,
) -> Result<bool, SetError<CalendarProperty>> {
    let mut has_acl_changes = false;

    for (property, value) in updates.into_expanded_object() {
        let Key::Property(property) = property else {
            return Err(SetError::invalid_properties()
                .with_property(property.to_owned())
                .with_description("Invalid property."));
        };

        match (property, value) {
            (CalendarProperty::Name, Value::Str(value)) if (1..=255).contains(&value.len()) => {
                calendar.preferences_mut(access_token).name = value.into_owned();
            }
            (CalendarProperty::Description, Value::Str(value)) if value.len() < 255 => {
                calendar.preferences_mut(access_token).description = value.into_owned().into();
            }
            (CalendarProperty::Description, Value::Null) => {
                calendar.preferences_mut(access_token).description = None;
            }
            (CalendarProperty::SortOrder, Value::Number(value)) => {
                calendar.preferences_mut(access_token).sort_order = value.cast_to_u64() as u32;
            }
            (CalendarProperty::IsSubscribed, Value::Bool(subscribe)) => {
                let account_id = access_token.primary_id();
                if subscribe {
                    if !calendar.subscribers.contains(&account_id) {
                        calendar.subscribers.push(account_id);
                    }
                } else {
                    calendar.subscribers.retain(|id| *id != account_id);
                }
            }
            (CalendarProperty::ShareWith, value) => {
                calendar.acls = JmapRights::acl_set::<calendar::Calendar>(value)?;
                has_acl_changes = true;
            }
            (CalendarProperty::Pointer(pointer), value)
                if matches!(
                    pointer.first(),
                    Some(JsonPointerItem::Key(Key::Property(
                        CalendarProperty::ShareWith
                    )))
                ) =>
            {
                let mut pointer = pointer.iter();
                pointer.next();

                calendar.acls = JmapRights::acl_patch::<calendar::Calendar>(
                    std::mem::take(&mut calendar.acls),
                    pointer,
                    value,
                )?;
                has_acl_changes = true;
            }
            (property, _) => {
                return Err(SetError::invalid_properties()
                    .with_property(property.clone())
                    .with_description("Field could not be set."));
            }
        }
    }

    // Validate name
    if calendar.preferences(access_token).name.is_empty() {
        return Err(SetError::invalid_properties()
            .with_property(CalendarProperty::Name)
            .with_description("Missing name."));
    }

    Ok(has_acl_changes)
}
*/
