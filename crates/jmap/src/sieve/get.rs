/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    api::metadata::{MetadataDocuments, MetadataType, ObjectMetadata, select_properties},
    changes::state::StateManager,
};
use common::{Server, auth::AccessToken};
use email::sieve::{SieveScript, ingest::SieveScriptIngest};
use jmap_proto::{
    method::get::{GetRequest, GetResponse, all_ids},
    object::sieve::{Sieve, SieveProperty, SieveValue},
    request::capability::CapabilityIds,
};
use jmap_tools::{Map, Value};
use std::future::Future;
use store::{
    ValueKey,
    write::{Archive, ArchiveBytes},
};
use trc::AddContext;
use types::{
    blob::{BlobClass, BlobId, BlobSection},
    collection::{Collection, SyncCollection},
    field::SieveField,
};

pub trait SieveScriptGet: Sync + Send {
    fn sieve_script_get(
        &self,
        request: GetRequest<Sieve>,
        access_token: &AccessToken,
        using: CapabilityIds,
    ) -> impl Future<Output = trc::Result<GetResponse<Sieve>>> + Send;
}

impl SieveScriptGet for Server {
    async fn sieve_script_get(
        &self,
        mut request: GetRequest<Sieve>,
        access_token: &AccessToken,
        using: CapabilityIds,
    ) -> trc::Result<GetResponse<Sieve>> {
        let (ids, not_found_ids) = request.unwrap_ids(self.core.jmap.get_max_objects)?;
        let (properties, selection) = select_properties(
            &mut request,
            &[
                SieveProperty::Id,
                SieveProperty::Name,
                SieveProperty::BlobId,
                SieveProperty::IsActive,
            ],
            using,
        )?;
        let object_metadata =
            ObjectMetadata::new(self, access_token, using, MetadataType::SieveScript);
        let metadata = object_metadata.get(selection);
        let metadata_slots = metadata.as_ref().map_or(0, |get| {
            usize::from(get.wants_shared()) + usize::from(get.wants_private())
        });
        let mut documents = MetadataDocuments::default();
        let mut listed = Vec::new();
        let account_id = request.account_id.document_id();
        let sampled = object_metadata.viewer_change_id(self, account_id).await?;
        let script_ids = self
            .document_ids(account_id, Collection::SieveScript, SieveField::Name)
            .await?;
        let ids = if let Some(ids) = ids {
            ids
        } else {
            all_ids(
                script_ids.iter().map(Into::into),
                self.core.jmap.get_max_objects,
            )?
        };
        let mut response = GetResponse {
            account_id: request.account_id.into(),
            state: sampled
                .state(
                    self.get_state(account_id, SyncCollection::SieveScript)
                        .await?,
                )
                .into(),
            list: Vec::with_capacity(ids.len()),
            not_found: not_found_ids,
        };
        let active_script_id = self.sieve_script_get_active_id(account_id).await?;

        for id in ids {
            // Obtain the sieve script object
            let document_id = id.document_id();
            if !script_ids.contains(document_id) {
                response.push_not_found(id);
                continue;
            }
            let sieve_ = if let Some(sieve) = self
                .store()
                .get_value::<Archive<ArchiveBytes>>(ValueKey::archive(
                    account_id,
                    Collection::SieveScript,
                    document_id,
                ))
                .await?
            {
                sieve
            } else {
                response.push_not_found(id);
                continue;
            };
            let sieve = sieve_
                .unarchive::<SieveScript>()
                .caused_by(trc::location!())?;
            let mut result = Map::with_capacity(properties.len() + metadata_slots);
            for property in &properties {
                match property {
                    SieveProperty::Id => {
                        result.insert_unchecked(SieveProperty::Id, id);
                    }
                    SieveProperty::Name => {
                        result.insert_unchecked(SieveProperty::Name, &sieve.name);
                    }
                    SieveProperty::IsActive => {
                        result.insert_unchecked(
                            SieveProperty::IsActive,
                            active_script_id == Some(document_id),
                        );
                    }
                    SieveProperty::BlobId => {
                        let blob_id = BlobId {
                            hash: (&sieve.blob_hash).into(),
                            class: BlobClass::Linked {
                                account_id,
                                collection: Collection::SieveScript.into(),
                                document_id,
                            },
                            section: BlobSection::new(0, u32::from(sieve.size) as usize, 0).into(),
                        };

                        result.insert_unchecked(
                            SieveProperty::BlobId,
                            Value::Element(SieveValue::BlobId(blob_id)),
                        );
                    }
                    SieveProperty::Metadata
                    | SieveProperty::PrivateMetadata
                    | SieveProperty::Pointer(_) => unreachable!(),
                }
            }
            if metadata.is_some() {
                documents.insert(document_id, sieve.metadata_kinds());
                listed.push(document_id);
            }
            response.list.push(result.into());
        }

        if let Some(metadata) = &metadata {
            let mut values = object_metadata
                .load::<SieveProperty, SieveValue>(self, account_id, metadata, &documents)
                .await?;
            for (value, document_id) in response.list.iter_mut().zip(listed) {
                if let Value::Object(object) = value {
                    values.insert_into(document_id, object);
                }
            }
        }

        Ok(response)
    }
}
