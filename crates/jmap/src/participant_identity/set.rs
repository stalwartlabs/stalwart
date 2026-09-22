/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::participant_identity::get::ParticipantIdentityGet;
use common::{Server, ipc::PushNotification};
use groupware::{
    calendar::{ParticipantIdentities, ParticipantIdentity, ParticipantIdentityChangeType},
    strip_mailto_scheme,
};
use jmap_proto::{
    error::set::{SetError, SetErrorType},
    method::set::{SetRequest, SetResponse},
    object::participant_identity::{self, ParticipantIdentityProperty, ParticipantIdentityValue},
    request::{MaybeInvalid, reference::MaybeIdReference},
    types::state::State,
};
use jmap_tools::{Key, Value};
use registry::schema::prelude::StorageQuota;
use store::{
    Serialize,
    ahash::AHashSet,
    write::{Archiver, BatchBuilder},
};
use trc::AddContext;
use types::{
    collection::Collection,
    field::PrincipalField,
    id::Id,
    type_state::{DataType, StateChange},
};
use utils::sanitize_email;

pub trait ParticipantIdentitySet: Sync + Send {
    fn participant_identity_set(
        &self,
        request: SetRequest<'_, participant_identity::ParticipantIdentity>,
    ) -> impl Future<Output = trc::Result<SetResponse<participant_identity::ParticipantIdentity>>> + Send;
}

impl ParticipantIdentitySet for Server {
    async fn participant_identity_set(
        &self,
        mut request: SetRequest<'_, participant_identity::ParticipantIdentity>,
    ) -> trc::Result<SetResponse<participant_identity::ParticipantIdentity>> {
        let account_id = request.account_id.document_id();
        let mut response = SetResponse::from_request(&request, self.core.jmap.set_max_objects)?;
        let will_destroy = response.collect_will_destroy(request.unwrap_destroy());
        let (identity_archive, mut identities) =
            match self.participant_identity_get_or_create(account_id).await? {
                Some(archive) => {
                    let identities = archive
                        .deserialize::<ParticipantIdentities>()
                        .caused_by(trc::location!())?;

                    (Some(archive), identities)
                }
                None => (None, ParticipantIdentities::default()),
            };

        let old_state = identity_state(identities.change_id);
        if request
            .if_in_state
            .as_ref()
            .is_some_and(|if_in_state| if_in_state != &old_state)
        {
            return Err(trc::JmapEvent::StateMismatch.into_err());
        }
        response = response.with_state(old_state);

        let account_info = self
            .account_info(account_id)
            .await
            .caused_by(trc::location!())?;

        // Obtain allowed emails
        let allowed_emails = account_info
            .addresses()
            .iter()
            .map(|v| v.as_str())
            .collect::<AHashSet<_>>();

        // Process creates
        let mut has_changes = false;
        let mut new_default = None;
        let previous_default = identities.default;
        let mut created_ids = Vec::new();
        'create: for (id, object) in request.unwrap_create() {
            let mut identity = ParticipantIdentity::default();
            let client_name = object
                .as_object_and_get(&Key::Property(ParticipantIdentityProperty::Name))
                .is_some();
            let client_address = object
                .as_object_and_get(&Key::Property(ParticipantIdentityProperty::CalendarAddress))
                .and_then(|value| value.as_str())
                .map(|value| value.into_owned());

            if let Err(err) = validate_identity_value(None, object, &mut identity, &allowed_emails)
            {
                response.not_created.append(id, err);
                continue 'create;
            }

            if identities
                .identities
                .iter()
                .any(|i| i.calendar_address == identity.calendar_address)
            {
                response.not_created.append(id, address_in_use());
                continue 'create;
            }

            // Validate quota
            if identities.identities.len()
                >= self.object_quota(
                    account_info.object_quotas(),
                    StorageQuota::MaxParticipantIdentities,
                ) as usize
            {
                response.not_created.append(
                    id,
                    SetError::new(SetErrorType::OverQuota).with_description(concat!(
                        "There are too many identities, ",
                        "please delete some before adding a new one."
                    )),
                );
                continue 'create;
            }

            let document_id = identities
                .identities
                .iter()
                .map(|i| i.id)
                .max()
                .unwrap_or_default()
                + 1;
            identity.id = document_id;
            identities.identities.push(identity);

            if let Some(MaybeIdReference::Reference(id_ref)) =
                &request.arguments.on_success_set_is_default
                && id_ref == &id
            {
                new_default = Some(document_id);
            }

            has_changes = true;
            let calendar_address = identities
                .identities
                .last()
                .map(|identity| identity.calendar_address.clone())
                .unwrap_or_default();
            response.created(id.clone(), document_id);
            response.add_created_properties(
                &id,
                (!client_name)
                    .then(|| {
                        (
                            ParticipantIdentityProperty::Name,
                            Value::Str(identities.default_name.clone().into()),
                        )
                    })
                    .into_iter()
                    .chain(
                        (client_address.as_deref() != Some(calendar_address.as_str())).then(|| {
                            (
                                ParticipantIdentityProperty::CalendarAddress,
                                Value::Str(calendar_address.into()),
                            )
                        }),
                    ),
            );
            created_ids.push(document_id);
        }

        // Process updates
        'update: for (id, object) in request.unwrap_update() {
            let id = match id {
                MaybeInvalid::Value(id) => id,
                invalid => {
                    response.not_updated.append(invalid, SetError::not_found());
                    continue 'update;
                }
            };
            // Make sure id won't be destroyed
            if will_destroy.contains(&id) {
                response.not_updated.append(id, SetError::will_destroy());
                continue 'update;
            }

            let document_id = id.document_id();
            let Some(identity) = identities
                .identities
                .iter_mut()
                .find(|i| i.id == document_id)
            else {
                response.not_updated.append(id, SetError::not_found());
                continue 'update;
            };

            let mut updated_identity = identity.clone();
            let client_address = object
                .as_object_and_get(&Key::Property(ParticipantIdentityProperty::CalendarAddress))
                .and_then(|value| value.as_str())
                .map(|value| value.into_owned());
            if let Err(err) =
                validate_identity_value(Some(id), object, &mut updated_identity, &allowed_emails)
            {
                response.not_updated.append(id, err);
                continue 'update;
            }
            if identities.identities.iter().any(|i| {
                i.id != document_id && i.calendar_address == updated_identity.calendar_address
            }) {
                response.not_updated.append(id, address_in_use());
                continue 'update;
            }
            let normalized_address = client_address
                .is_some_and(|address| address != updated_identity.calendar_address)
                .then(|| updated_identity.calendar_address.clone());
            if let Some(identity) = identities
                .identities
                .iter_mut()
                .find(|i| i.id == document_id)
            {
                *identity = updated_identity;
            }

            has_changes = true;
            response.updated.append(id, None);
            if let Some(address) = normalized_address {
                response.add_server_set_property(
                    id,
                    ParticipantIdentityProperty::CalendarAddress,
                    Value::Str(address.into()),
                );
            }
        }

        // Process deletions
        for id in &will_destroy {
            let document_id = id.document_id();
            if identities.identities.iter().any(|i| i.id == document_id) {
                response.destroyed.push(*id);
            } else {
                response.not_destroyed.append(*id, SetError::not_found());
            }
        }
        if !response.destroyed.is_empty() {
            has_changes = true;
            identities
                .identities
                .retain(|i| !response.destroyed.iter().any(|id| id.document_id() == i.id));
        }

        if let Some(MaybeIdReference::Id(id)) = request.arguments.on_success_set_is_default {
            new_default = Some(id.document_id());
        }
        if let Some(default_id) = new_default.filter(|default_id| {
            response.not_created.is_empty()
                && response.not_updated.is_empty()
                && response.not_destroyed.is_empty()
                && identities.identities.iter().any(|i| i.id == *default_id)
        }) {
            identities.default = default_id;
        } else if !identities
            .identities
            .iter()
            .any(|i| i.id == identities.default)
            && let Some(first) = identities.identities.first()
        {
            identities.default = first.id;
        }
        for document_id in created_ids
            .iter()
            .filter(|document_id| **document_id != identities.default)
        {
            response.add_server_set_property(
                Id::from(*document_id),
                ParticipantIdentityProperty::IsDefault,
                false,
            );
        }
        if identities.default != previous_default {
            has_changes = true;
            response.add_server_set_property(
                Id::from(identities.default),
                ParticipantIdentityProperty::IsDefault,
                true,
            );
            if identities
                .identities
                .iter()
                .any(|i| i.id == previous_default)
            {
                response.add_server_set_property(
                    Id::from(previous_default),
                    ParticipantIdentityProperty::IsDefault,
                    false,
                );
            }
        }

        // Write changes
        if has_changes {
            identities.begin_changes();
            let changed_defaults = [identities.default, previous_default]
                .into_iter()
                .filter(|_| identities.default != previous_default);
            let updated_ids = response
                .updated
                .keys()
                .map(|id| id.document_id())
                .chain(changed_defaults)
                .filter(|id| {
                    !created_ids.contains(id)
                        && !response
                            .destroyed
                            .iter()
                            .any(|destroyed| destroyed.document_id() == *id)
                })
                .collect::<AHashSet<_>>();
            for (id, change_type) in created_ids
                .iter()
                .map(|id| (*id, ParticipantIdentityChangeType::Created))
                .chain(
                    updated_ids
                        .into_iter()
                        .map(|id| (id, ParticipantIdentityChangeType::Updated)),
                )
                .chain(
                    response
                        .destroyed
                        .iter()
                        .map(|id| (id.document_id(), ParticipantIdentityChangeType::Destroyed)),
                )
            {
                identities.record_change(id, change_type);
            }
            let change_id = identities.change_id;
            let mut batch = BatchBuilder::new();
            batch
                .with_account_id(account_id)
                .with_collection(Collection::Principal)
                .with_document(0);
            if let Some(archive) = identity_archive {
                batch.assert_value(PrincipalField::ParticipantIdentities, archive);
            }
            batch.set(
                PrincipalField::ParticipantIdentities,
                Archiver::new(identities)
                    .serialize()
                    .caused_by(trc::location!())?,
            );

            self.commit_batch(batch).await.caused_by(trc::location!())?;
            response.new_state = Some(identity_state(change_id));
            self.broadcast_push_notification(PushNotification::StateChange(
                StateChange::new(account_id)
                    .with_change_id(change_id as u64)
                    .with_change(DataType::ParticipantIdentity),
            ))
            .await;
        }

        Ok(response)
    }
}

fn validate_identity_value(
    expected_id: Option<Id>,
    update: Value<'_, ParticipantIdentityProperty, ParticipantIdentityValue>,
    identity: &mut ParticipantIdentity,
    allowed_emails: &AHashSet<&str>,
) -> Result<(), SetError<ParticipantIdentityProperty>> {
    for (property, value) in update.into_expanded_object() {
        let Key::Property(property) = property else {
            return Err(SetError::invalid_properties()
                .with_property(property.to_owned())
                .with_description("Invalid property."));
        };

        match (property, value) {
            (ParticipantIdentityProperty::Name, Value::Str(value)) if value.len() < 255 => {
                identity.name = value.into_owned().into();
            }
            (ParticipantIdentityProperty::CalendarAddress, Value::Str(value)) => {
                if identity.calendar_address != value {
                    let email = sanitize_email(strip_mailto_scheme(&value));

                    if let Some(email) = email {
                        if allowed_emails.iter().any(|e| e == &email) {
                            identity.calendar_address = format!("mailto:{email}");
                        } else {
                            return Err(SetError::forbidden().with_description(
                                "Calendar address not configured for this account.",
                            ));
                        }
                    } else {
                        return Err(SetError::invalid_properties()
                            .with_property(ParticipantIdentityProperty::CalendarAddress)
                            .with_description("Invalid or missing calendar address.".to_string()));
                    }
                }
            }
            (ParticipantIdentityProperty::Id, value) => {
                if !expected_id.is_some_and(|expected| crate::matches_id(&value, expected)) {
                    return Err(SetError::invalid_properties()
                        .with_property(ParticipantIdentityProperty::Id)
                        .with_description("The id property is immutable."));
                }
            }
            (property, _) => {
                return Err(SetError::invalid_properties()
                    .with_property(property.clone())
                    .with_description("Field could not be set."));
            }
        }
    }

    // Validate email address
    if !identity.calendar_address.is_empty() {
        Ok(())
    } else {
        Err(SetError::invalid_properties()
            .with_property(ParticipantIdentityProperty::CalendarAddress)
            .with_description("Missing calendar address."))
    }
}

fn address_in_use() -> SetError<ParticipantIdentityProperty> {
    SetError::forbidden().with_description("Calendar address already in use.")
}

pub(crate) fn identity_state(change_id: u32) -> State {
    State::from((change_id != 0).then_some(change_id as u64))
}
