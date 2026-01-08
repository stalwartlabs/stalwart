/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::participant_identity::get::ParticipantIdentityGet;
use common::{Server, auth::AccessToken};
use directory::QueryParams;
use groupware::calendar::{ParticipantIdentities, ParticipantIdentity};
use jmap_proto::{
    error::set::{SetError, SetErrorType},
    method::set::{SetRequest, SetResponse},
    object::participant_identity::{self, ParticipantIdentityProperty, ParticipantIdentityValue},
    request::{IntoValid, reference::MaybeIdReference},
};
use jmap_tools::{Key, Value};
use store::{
    Serialize,
    ahash::AHashSet,
    write::{Archiver, BatchBuilder},
};
use trc::AddContext;
use types::{collection::Collection, field::PrincipalField};
use utils::sanitize_email;

pub trait ParticipantIdentitySet: Sync + Send {
    fn participant_identity_set(
        &self,
        request: SetRequest<'_, participant_identity::ParticipantIdentity>,
        access_token: &AccessToken,
    ) -> impl Future<Output = trc::Result<SetResponse<participant_identity::ParticipantIdentity>>> + Send;
}

impl ParticipantIdentitySet for Server {
    async fn participant_identity_set(
        &self,
        mut request: SetRequest<'_, participant_identity::ParticipantIdentity>,
        access_token: &AccessToken,
    ) -> trc::Result<SetResponse<participant_identity::ParticipantIdentity>> {
        let account_id = request.account_id.document_id();
        let mut response = SetResponse::from_request(&request, self.core.jmap.set_max_objects)?;
        let will_destroy = request.unwrap_destroy().into_valid().collect::<Vec<_>>();
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

        // Obtain allowed emails
        let allowed_emails = self
            .directory()
            .query(QueryParams::id(account_id).with_return_member_of(false))
            .await?
            .map(|p| p.into_email_addresses().collect::<AHashSet<_>>())
            .unwrap_or_default();

        // Process creates
        let mut has_changes = false;
        'create: for (id, object) in request.unwrap_create() {
            let mut identity = ParticipantIdentity::default();

            if let Err(err) = validate_identity_value(object, &mut identity, &allowed_emails) {
                response.not_created.append(id, err);
                continue 'create;
            }

            if identities
                .identities
                .iter()
                .any(|i| i.calendar_address == identity.calendar_address)
            {
                response.not_created.append(
                    id,
                    SetError::invalid_properties()
                        .with_property(ParticipantIdentityProperty::CalendarAddress)
                        .with_description("Calendar address already in use.".to_string()),
                );
                continue 'create;
            }

            // Validate quota
            if identities.identities.len()
                >= access_token.object_quota(Collection::Identity) as usize
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
                identities.default = document_id;
            }

            has_changes = true;
            response.created(id, document_id);
        }

        // Process updates
        'update: for (id, object) in request.unwrap_update().into_valid() {
            // Make sure id won't be destroyed
            if will_destroy.contains(&id) {
                response.not_updated.append(id, SetError::will_destroy());
                continue 'update;
            }

            let Some(identity) = identities
                .identities
                .iter_mut()
                .find(|i| i.id == id.document_id())
            else {
                response.not_updated.append(id, SetError::not_found());
                continue 'update;
            };

            if let Err(err) = validate_identity_value(object, identity, &allowed_emails) {
                response.not_updated.append(id, err);
                continue 'update;
            }

            has_changes = true;
            response.updated.append(id, None);
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
            let id = id.document_id();
            if identities.identities.iter().any(|i| i.id == id) {
                identities.default = id;
                has_changes = true;
            }
        }

        // Write changes
        if has_changes {
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
        }

        Ok(response)
    }
}

fn validate_identity_value(
    update: Value<'_, ParticipantIdentityProperty, ParticipantIdentityValue>,
    identity: &mut ParticipantIdentity,
    allowed_emails: &AHashSet<String>,
) -> Result<(), SetError<ParticipantIdentityProperty>> {
    let mut changed_address = false;
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
                    changed_address = true;
                    identity.calendar_address = value.into_owned();
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
        if !changed_address {
            return Ok(());
        }

        let email = if let Some(email) = identity.calendar_address.strip_prefix("mailto:") {
            sanitize_email(email)
        } else {
            sanitize_email(&identity.calendar_address)
        };

        if let Some(email) = email {
            if allowed_emails.iter().any(|e| e == &email) {
                identity.calendar_address = format!("mailto:{email}");
                Ok(())
            } else {
                Err(SetError::invalid_properties()
                    .with_property(ParticipantIdentityProperty::CalendarAddress)
                    .with_description(
                        "Calendar address not configured for this account.".to_string(),
                    ))
            }
        } else {
            Err(SetError::invalid_properties()
                .with_property(ParticipantIdentityProperty::CalendarAddress)
                .with_description("Invalid or missing calendar address.".to_string()))
        }
    } else {
        Err(SetError::invalid_properties()
            .with_property(ParticipantIdentityProperty::CalendarAddress)
            .with_description("Missing calendar address."))
    }
}
