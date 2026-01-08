/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use common::Server;
use directory::{PrincipalData, QueryParams};
use groupware::calendar::{ParticipantIdentities, ParticipantIdentity};
use jmap_proto::{
    method::get::{GetRequest, GetResponse},
    object::participant_identity::{self, ParticipantIdentityProperty, ParticipantIdentityValue},
};
use jmap_tools::{Map, Value};
use store::{
    Serialize, ValueKey,
    write::{AlignedBytes, Archive, Archiver, BatchBuilder},
};
use trc::AddContext;
use types::{collection::Collection, field::PrincipalField, id::Id};

pub trait ParticipantIdentityGet: Sync + Send {
    fn participant_identity_get(
        &self,
        request: GetRequest<participant_identity::ParticipantIdentity>,
    ) -> impl Future<Output = trc::Result<GetResponse<participant_identity::ParticipantIdentity>>> + Send;

    fn participant_identity_get_or_create(
        &self,
        account_id: u32,
    ) -> impl Future<Output = trc::Result<Option<Archive<AlignedBytes>>>> + Send;
}

impl ParticipantIdentityGet for Server {
    async fn participant_identity_get(
        &self,
        mut request: GetRequest<participant_identity::ParticipantIdentity>,
    ) -> trc::Result<GetResponse<participant_identity::ParticipantIdentity>> {
        let ids = request.unwrap_ids(self.core.jmap.get_max_objects)?;
        let properties = request.unwrap_properties(&[
            ParticipantIdentityProperty::Id,
            ParticipantIdentityProperty::Name,
            ParticipantIdentityProperty::CalendarAddress,
            ParticipantIdentityProperty::IsDefault,
        ]);
        let account_id = request.account_id.document_id();
        let identities = self.participant_identity_get_or_create(account_id).await?;

        let mut response = GetResponse {
            account_id: request.account_id.into(),
            state: None,
            list: Vec::new(),
            not_found: vec![],
        };

        let Some(identities) = identities else {
            response.not_found = ids.unwrap_or_default();
            return Ok(response);
        };

        let identities = identities
            .unarchive::<ParticipantIdentities>()
            .caused_by(trc::location!())?;

        let ids = if let Some(ids) = ids {
            ids
        } else {
            identities
                .identities
                .iter()
                .take(self.core.jmap.get_max_objects)
                .map(|i| Id::from(i.id.to_native()))
                .collect::<Vec<_>>()
        };

        for id in ids {
            // Obtain the identity object
            let document_id = id.document_id();
            let Some(identity) = identities.identities.iter().find(|i| i.id == document_id) else {
                response.not_found.push(id);
                continue;
            };

            let mut result = Map::with_capacity(properties.len());
            for property in &properties {
                let value = match &property {
                    ParticipantIdentityProperty::Id => {
                        Value::Element(ParticipantIdentityValue::Id(id))
                    }
                    ParticipantIdentityProperty::Name => Value::Str(
                        identity
                            .name
                            .as_ref()
                            .map(|n| n.as_str())
                            .unwrap_or(identities.default_name.as_str())
                            .to_string()
                            .into(),
                    ),
                    ParticipantIdentityProperty::CalendarAddress => {
                        Value::Str(identity.calendar_address.to_string().into())
                    }
                    ParticipantIdentityProperty::IsDefault => {
                        Value::Bool(identities.default == document_id)
                    }
                };
                result.insert_unchecked(property.clone(), value);
            }
            response.list.push(result.into());
        }

        Ok(response)
    }

    async fn participant_identity_get_or_create(
        &self,
        account_id: u32,
    ) -> trc::Result<Option<Archive<AlignedBytes>>> {
        if let Some(identities) = self
            .store()
            .get_value::<Archive<AlignedBytes>>(ValueKey::property(
                account_id,
                Collection::Principal,
                0,
                PrincipalField::ParticipantIdentities,
            ))
            .await?
        {
            return Ok(Some(identities));
        }

        // Obtain principal
        let principal = if let Some(principal) = self
            .core
            .storage
            .directory
            .query(QueryParams::id(account_id).with_return_member_of(false))
            .await
            .caused_by(trc::location!())?
        {
            principal
        } else {
            return Ok(None);
        };
        let mut emails = Vec::new();
        let mut description = None;
        for data in principal.data {
            match data {
                PrincipalData::PrimaryEmail(v) | PrincipalData::EmailAlias(v) => emails.push(v),
                PrincipalData::Description(v) => description = Some(v),
                _ => {}
            }
        }
        let num_emails = emails.len();
        if num_emails == 0 {
            return Ok(None);
        }

        // Build identities
        let identities = ParticipantIdentities {
            identities: emails
                .iter()
                .enumerate()
                .map(|(id, email)| ParticipantIdentity {
                    id: id as u32,
                    name: None,
                    calendar_address: format!("mailto:{email}"),
                })
                .collect(),
            default: 0,
            default_name: description.unwrap_or(principal.name),
        };

        let mut batch = BatchBuilder::new();
        batch
            .with_account_id(account_id)
            .with_collection(Collection::Principal)
            .with_document(0)
            .set(
                PrincipalField::ParticipantIdentities,
                Archiver::new(identities)
                    .serialize()
                    .caused_by(trc::location!())?,
            );

        self.commit_batch(batch).await.caused_by(trc::location!())?;

        self.store()
            .get_value::<Archive<AlignedBytes>>(ValueKey::property(
                account_id,
                Collection::Principal,
                0,
                PrincipalField::ParticipantIdentities,
            ))
            .await
    }
}
