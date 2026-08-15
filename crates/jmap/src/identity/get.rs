/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::changes::state::StateManager;
use common::{Server, storage::index::ObjectIndexBuilder};
use email::identity::{ArchivedEmailAddress, Identity};
use jmap_proto::{
    method::get::{GetRequest, GetResponse},
    object::identity::{self, IdentityProperty, IdentityValue},
};
use jmap_tools::{Map, Value};
use std::{collections::BTreeSet, future::Future};
use store::{
    SerializeInfallible, ValueKey,
    rkyv::{option::ArchivedOption, vec::ArchivedVec},
    roaring::RoaringBitmap,
    write::{AlignedBytes, Archive, BatchBuilder, assert::AssertValue},
    xxhash_rust::xxh3::Xxh3,
};
use trc::AddContext;
use types::{
    collection::{Collection, SyncCollection},
    field::{Field, IdentityField, PrincipalField},
};

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
        let (ids, not_found_ids) = request.unwrap_ids(self.core.jmap.get_max_objects)?;
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
            not_found: not_found_ids,
        };

        for id in ids {
            // Obtain the identity object
            let document_id = id.document_id();
            if !identity_ids.contains(document_id) {
                response.push_not_found(id);
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
                response.push_not_found(id);
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
        // Obtain account info
        let account_info = self
            .account_info(account_id)
            .await
            .caused_by(trc::location!())?;
        let addresses = account_info
            .addresses()
            .iter()
            .map(|a| a.as_str())
            .collect::<BTreeSet<_>>();

        let mut hasher = Xxh3::new();
        for address in &addresses {
            hasher.update(address.as_bytes());
            hasher.update(b"\n");
        }
        let addresses_hash = hasher.digest();
        let stored_hash = self
            .store()
            .get_value::<u64>(ValueKey::property(
                account_id,
                Collection::Principal,
                0,
                PrincipalField::IdentityAddresses,
            ))
            .await
            .caused_by(trc::location!())?;

        let mut identity_ids = self
            .document_ids(account_id, Collection::Identity, IdentityField::DocumentId)
            .await?;
        if stored_hash == Some(addresses_hash) {
            return Ok(identity_ids);
        }

        // Determine which addresses are missing and which identities are no longer valid
        let member_of = &account_info.account().id_member_of;
        let mut missing_addresses = addresses.clone();
        let mut obsolete_ids = Vec::new();
        for document_id in &identity_ids {
            if let Some(identity) = self
                .store()
                .get_value::<Archive<AlignedBytes>>(ValueKey::archive(
                    account_id,
                    Collection::Identity,
                    document_id,
                ))
                .await
                .caused_by(trc::location!())?
            {
                let email = identity
                    .unarchive::<Identity>()
                    .caused_by(trc::location!())?
                    .email
                    .as_str();

                if addresses.contains(email) {
                    missing_addresses.remove(email);
                } else if !self
                    .account_id_from_email(email, true)
                    .await
                    .caused_by(trc::location!())?
                    .is_some_and(|id| id == account_id || member_of.contains(&id))
                {
                    obsolete_ids.push(document_id);
                }
            }
        }

        let mut batch = BatchBuilder::new();
        batch
            .with_account_id(account_id)
            .with_collection(Collection::Identity);

        // Create identities for the new addresses
        if !missing_addresses.is_empty() {
            let name = account_info.description().unwrap_or(account_info.name());
            let mut next_document_id = self
                .store()
                .assign_document_ids(
                    account_id,
                    Collection::Identity,
                    missing_addresses.len() as u64,
                )
                .await
                .caused_by(trc::location!())?;
            for email in missing_addresses {
                let name = if name.is_empty() {
                    email.to_string()
                } else {
                    name.to_string()
                };
                let document_id = next_document_id;
                next_document_id -= 1;
                batch
                    .with_document(document_id)
                    .tag(IdentityField::DocumentId)
                    .custom(ObjectIndexBuilder::<(), _>::new().with_changes(Identity {
                        name,
                        email: email.to_string(),
                        ..Default::default()
                    }))
                    .caused_by(trc::location!())?
                    .commit_point();
                identity_ids.insert(document_id);
            }
        }

        // Delete identities whose address no longer belongs to this account
        for document_id in obsolete_ids {
            batch
                .with_document(document_id)
                .untag(IdentityField::DocumentId)
                .clear(Field::ARCHIVE)
                .log_item_delete(SyncCollection::Identity, None)
                .commit_point();
            identity_ids.remove(document_id);
        }

        batch
            .with_collection(Collection::Principal)
            .with_document(0)
            .assert_value(
                PrincipalField::IdentityAddresses,
                stored_hash.map_or(AssertValue::None, AssertValue::U64),
            )
            .set(
                PrincipalField::IdentityAddresses,
                addresses_hash.serialize(),
            );

        match self.commit_batch(batch).await {
            Ok(_) => Ok(identity_ids),
            Err(err) if err.is_assertion_failure() => self
                .document_ids(account_id, Collection::Identity, IdentityField::DocumentId)
                .await
                .caused_by(trc::location!()),
            Err(err) => Err(err.caused_by(trc::location!())),
        }
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
