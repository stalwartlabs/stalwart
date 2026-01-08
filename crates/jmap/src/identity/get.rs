/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::changes::state::StateManager;
use common::{Server, storage::index::ObjectIndexBuilder};
use directory::{PrincipalData, QueryParams};
use email::identity::{ArchivedEmailAddress, Identity};
use jmap_proto::{
    method::get::{GetRequest, GetResponse},
    object::identity::{self, IdentityProperty, IdentityValue},
};
use jmap_tools::{Map, Value};
use std::future::Future;
use store::{
    ValueKey, rkyv::{option::ArchivedOption, vec::ArchivedVec}, roaring::RoaringBitmap, write::{AlignedBytes, Archive, BatchBuilder}
};
use trc::AddContext;
use types::{
    collection::{Collection, SyncCollection},
    field::IdentityField,
};
use utils::sanitize_email;

pub trait IdentityGet: Sync + Send {
    fn identity_get(
        &self,
        request: GetRequest<identity::Identity>,
    ) -> impl Future<Output = trc::Result<GetResponse<identity::Identity>>> + Send;

    fn identity_get_or_create(
        &self,
        account_id: u32,
    ) -> impl Future<Output = trc::Result<RoaringBitmap>> + Send;
}

impl IdentityGet for Server {
    async fn identity_get(
        &self,
        mut request: GetRequest<identity::Identity>,
    ) -> trc::Result<GetResponse<identity::Identity>> {
        let ids = request.unwrap_ids(self.core.jmap.get_max_objects)?;
        let properties = request.unwrap_properties(&[
            IdentityProperty::Id,
            IdentityProperty::Name,
            IdentityProperty::Email,
            IdentityProperty::ReplyTo,
            IdentityProperty::Bcc,
            IdentityProperty::TextSignature,
            IdentityProperty::HtmlSignature,
            IdentityProperty::MayDelete,
        ]);
        let account_id = request.account_id.document_id();
        let identity_ids = self.identity_get_or_create(account_id).await?;
        let ids = if let Some(ids) = ids {
            ids
        } else {
            identity_ids
                .iter()
                .take(self.core.jmap.get_max_objects)
                .map(Into::into)
                .collect::<Vec<_>>()
        };
        let mut response = GetResponse {
            account_id: request.account_id.into(),
            state: self
                .get_state(account_id, SyncCollection::Identity)
                .await?
                .into(),
            list: Vec::with_capacity(ids.len()),
            not_found: vec![],
        };

        for id in ids {
            // Obtain the identity object
            let document_id = id.document_id();
            if !identity_ids.contains(document_id) {
                response.not_found.push(id);
                continue;
            }
            let _identity = if let Some(identity) = self
                .store()
                .get_value::<Archive<AlignedBytes>>(ValueKey::archive(
                    account_id,
                    Collection::Identity,
                    document_id,
                ))
                .await?
            {
                identity
            } else {
                response.not_found.push(id);
                continue;
            };
            let identity = _identity
                .unarchive::<Identity>()
                .caused_by(trc::location!())?;
            let mut result = Map::with_capacity(properties.len());
            for property in &properties {
                match property {
                    IdentityProperty::Id => {
                        result.insert_unchecked(IdentityProperty::Id, IdentityValue::Id(id));
                    }
                    IdentityProperty::MayDelete => {
                        result.insert_unchecked(IdentityProperty::MayDelete, Value::Bool(true));
                    }
                    IdentityProperty::Name => {
                        result.insert_unchecked(IdentityProperty::Name, identity.name.to_string());
                    }
                    IdentityProperty::Email => {
                        result
                            .insert_unchecked(IdentityProperty::Email, identity.email.to_string());
                    }
                    IdentityProperty::TextSignature => {
                        result.insert_unchecked(
                            IdentityProperty::TextSignature,
                            identity.text_signature.to_string(),
                        );
                    }
                    IdentityProperty::HtmlSignature => {
                        result.insert_unchecked(
                            IdentityProperty::HtmlSignature,
                            identity.html_signature.to_string(),
                        );
                    }
                    IdentityProperty::Bcc => {
                        result
                            .insert_unchecked(IdentityProperty::Bcc, email_to_value(&identity.bcc));
                    }
                    IdentityProperty::ReplyTo => {
                        result.insert_unchecked(
                            IdentityProperty::ReplyTo,
                            email_to_value(&identity.reply_to),
                        );
                    }
                    property => {
                        result.insert_unchecked(property.clone(), Value::Null);
                    }
                }
            }
            response.list.push(result.into());
        }

        Ok(response)
    }

    async fn identity_get_or_create(&self, account_id: u32) -> trc::Result<RoaringBitmap> {
        let mut identity_ids = self
            .document_ids(account_id, Collection::Identity, IdentityField::DocumentId)
            .await?;
        if !identity_ids.is_empty() {
            return Ok(identity_ids);
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
            return Ok(identity_ids);
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
            return Ok(identity_ids);
        }

        let mut batch = BatchBuilder::new();
        batch
            .with_account_id(account_id)
            .with_collection(Collection::Identity);

        // Create identities
        let name = description.unwrap_or(principal.name);
        let mut next_document_id = self
            .store()
            .assign_document_ids(account_id, Collection::Identity, num_emails as u64)
            .await
            .caused_by(trc::location!())?;
        for email in &emails {
            let email = sanitize_email(email).unwrap_or_default();
            if email.is_empty() || email.starts_with('@') {
                continue;
            }
            let name = if name.is_empty() {
                email.clone()
            } else {
                name.clone()
            };
            let document_id = next_document_id;
            next_document_id -= 1;
            batch
                .with_document(document_id)
                .tag(IdentityField::DocumentId)
                .custom(ObjectIndexBuilder::<(), _>::new().with_changes(Identity {
                    name,
                    email,
                    ..Default::default()
                }))
                .caused_by(trc::location!())?;
            identity_ids.insert(document_id);
        }
        self.commit_batch(batch).await.caused_by(trc::location!())?;

        Ok(identity_ids)
    }
}

fn email_to_value(
    email: &ArchivedOption<ArchivedVec<ArchivedEmailAddress>>,
) -> Value<'static, IdentityProperty, IdentityValue> {
    if let ArchivedOption::Some(email) = email {
        Value::Array(
            email
                .iter()
                .map(|email| {
                    Value::Object(
                        Map::with_capacity(2)
                            .with_key_value(IdentityProperty::Name, &email.name)
                            .with_key_value(IdentityProperty::Email, &email.email),
                    )
                })
                .collect(),
        )
    } else {
        Value::Null
    }
}
