/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::changes::state::StateManager;
use common::Server;
use email::sieve::SieveScript;
use jmap_proto::{
    method::get::{GetRequest, GetResponse},
    object::sieve::{Sieve, SieveProperty, SieveValue},
};
use jmap_tools::{Map, Value};
use std::future::Future;
use trc::AddContext;
use types::{
    blob::{BlobClass, BlobId, BlobSection},
    collection::{Collection, SyncCollection},
};

pub trait SieveScriptGet: Sync + Send {
    fn sieve_script_get(
        &self,
        request: GetRequest<Sieve>,
    ) -> impl Future<Output = trc::Result<GetResponse<Sieve>>> + Send;
}

impl SieveScriptGet for Server {
    async fn sieve_script_get(
        &self,
        mut request: GetRequest<Sieve>,
    ) -> trc::Result<GetResponse<Sieve>> {
        let ids = request.unwrap_ids(self.core.jmap.get_max_objects)?;
        let properties = request.unwrap_properties(&[
            SieveProperty::Id,
            SieveProperty::Name,
            SieveProperty::BlobId,
            SieveProperty::IsActive,
        ]);
        let account_id = request.account_id.document_id();
        let push_ids = self
            .get_document_ids(account_id, Collection::SieveScript)
            .await?
            .unwrap_or_default();
        let ids = if let Some(ids) = ids {
            ids
        } else {
            push_ids
                .iter()
                .take(self.core.jmap.get_max_objects)
                .map(Into::into)
                .collect::<Vec<_>>()
        };
        let mut response = GetResponse {
            account_id: request.account_id.into(),
            state: self
                .get_state(account_id, SyncCollection::SieveScript)
                .await?
                .into(),
            list: Vec::with_capacity(ids.len()),
            not_found: vec![],
        };

        for id in ids {
            // Obtain the sieve script object
            let document_id = id.document_id();
            if !push_ids.contains(document_id) {
                response.not_found.push(id);
                continue;
            }
            let sieve_ = if let Some(sieve) = self
                .get_archive(account_id, Collection::SieveScript, document_id)
                .await?
            {
                sieve
            } else {
                response.not_found.push(id);
                continue;
            };
            let sieve = sieve_
                .unarchive::<SieveScript>()
                .caused_by(trc::location!())?;
            let mut result = Map::with_capacity(properties.len());
            for property in &properties {
                match property {
                    SieveProperty::Id => {
                        result.insert_unchecked(SieveProperty::Id, id);
                    }
                    SieveProperty::Name => {
                        result.insert_unchecked(SieveProperty::Name, &sieve.name);
                    }
                    SieveProperty::IsActive => {
                        result.insert_unchecked(SieveProperty::IsActive, sieve.is_active);
                    }
                    SieveProperty::BlobId => {
                        let blob_id = BlobId {
                            hash: (&sieve.blob_hash).into(),
                            class: BlobClass::Linked {
                                account_id,
                                collection: Collection::SieveScript.into(),
                                document_id,
                            },
                            section: BlobSection {
                                size: u32::from(sieve.size) as usize,
                                ..Default::default()
                            }
                            .into(),
                        };

                        result.insert_unchecked(
                            SieveProperty::BlobId,
                            Value::Element(SieveValue::BlobId(blob_id)),
                        );
                    }
                }
            }
            response.list.push(result.into());
        }

        Ok(response)
    }
}
