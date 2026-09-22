/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{download::BlobDownload, embedded::EmbeddedBlobs};
use common::{Server, auth::AccessToken};
use email::message::messagedata::MessageData;
use jmap_proto::{
    method::{
        get::{GetRequest, GetResponse},
        lookup::{BlobInfo, BlobLookupRequest, BlobLookupResponse},
    },
    object::blob::{Blob, BlobProperty, BlobValue, DataProperty, DigestProperty},
    request::{IntoValid, MaybeInvalid},
};
use jmap_tools::{Map, Value};
use mail_builder::encoders::Base64Encoder;
use sha1::{Digest, Sha1};
use sha2::{Sha256, Sha512};
use std::future::Future;
use store::ValueKey;
use trc::AddContext;
use types::{blob::BlobClass, collection::Collection, id::Id, type_state::DataType};
use utils::map::vec_map::VecMap;

pub trait BlobOperations: Sync + Send {
    fn blob_get(
        &self,
        request: GetRequest<Blob>,
        access_token: &AccessToken,
    ) -> impl Future<Output = trc::Result<GetResponse<Blob>>> + Send;

    fn blob_lookup(
        &self,
        request: BlobLookupRequest,
    ) -> impl Future<Output = trc::Result<BlobLookupResponse>> + Send;
}

impl BlobOperations for Server {
    async fn blob_get(
        &self,
        mut request: GetRequest<Blob>,
        access_token: &AccessToken,
    ) -> trc::Result<GetResponse<Blob>> {
        let (ids, not_found_ids) = request.unwrap_ids(self.core.jmap.get_max_objects)?;
        let ids = ids.unwrap_or_default();
        let properties = request.unwrap_properties(&[
            BlobProperty::Id,
            BlobProperty::Data(DataProperty::Default),
            BlobProperty::Size,
        ]);
        let mut response = GetResponse {
            account_id: request.account_id.into(),
            state: None,
            list: Vec::with_capacity(ids.len()),
            not_found: not_found_ids,
        };

        let range_from = request.arguments.offset.unwrap_or(0);
        let range_to = request
            .arguments
            .length
            .map(|length| range_from.saturating_add(length))
            .unwrap_or(usize::MAX);

        for blob_id in ids {
            if let Some(bytes) = self.blob_download(&blob_id, access_token).await? {
                let mut blob = Map::with_capacity(properties.len());
                let bytes_range = if range_from == 0 && range_to == usize::MAX {
                    &bytes[..]
                } else {
                    let range_to = if range_to != usize::MAX && range_to > bytes.len() {
                        blob.insert_unchecked(BlobProperty::IsTruncated, true);
                        bytes.len()
                    } else {
                        range_to
                    };
                    bytes.get(range_from..range_to).unwrap_or_default()
                };

                for property in &properties {
                    let mut property = property.clone();
                    let value: Value<'static, BlobProperty, BlobValue> = match &property {
                        BlobProperty::Id => Value::Element(BlobValue::BlobId(blob_id.clone())),
                        BlobProperty::Size => bytes.len().into(),
                        BlobProperty::Digest(digest) => match digest {
                            DigestProperty::Sha => {
                                let mut hasher = Sha1::new();
                                hasher.update(bytes_range);
                                String::from_utf8(
                                    Base64Encoder::new()
                                        .encode(&hasher.finalize()[..])
                                        .unwrap_or_default(),
                                )
                                .unwrap()
                            }
                            DigestProperty::Sha256 => {
                                let mut hasher = Sha256::new();
                                hasher.update(bytes_range);
                                String::from_utf8(
                                    Base64Encoder::new()
                                        .encode(&hasher.finalize()[..])
                                        .unwrap_or_default(),
                                )
                                .unwrap()
                            }
                            DigestProperty::Sha512 => {
                                let mut hasher = Sha512::new();
                                hasher.update(bytes_range);
                                String::from_utf8(
                                    Base64Encoder::new()
                                        .encode(&hasher.finalize()[..])
                                        .unwrap_or_default(),
                                )
                                .unwrap()
                            }
                        }
                        .into(),
                        BlobProperty::Data(data) => match data {
                            DataProperty::AsText => match std::str::from_utf8(bytes_range) {
                                Ok(text) => text.to_string().into(),
                                Err(_) => {
                                    blob.insert_unchecked(BlobProperty::IsEncodingProblem, true);
                                    Value::Null
                                }
                            },
                            DataProperty::AsBase64 => String::from_utf8(
                                Base64Encoder::new().encode(bytes_range).unwrap_or_default(),
                            )
                            .unwrap()
                            .into(),
                            DataProperty::Default => match std::str::from_utf8(bytes_range) {
                                Ok(text) => {
                                    property = BlobProperty::Data(DataProperty::AsText);
                                    text.to_string().into()
                                }
                                Err(_) => {
                                    property = BlobProperty::Data(DataProperty::AsBase64);
                                    blob.insert_unchecked(BlobProperty::IsEncodingProblem, true);
                                    String::from_utf8(
                                        Base64Encoder::new()
                                            .encode(bytes_range)
                                            .unwrap_or_default(),
                                    )
                                    .unwrap()
                                    .into()
                                }
                            },
                        },
                        _ => Value::Null,
                    };
                    blob.insert_unchecked(property, value);
                }

                // Add result to response
                response.list.push(blob.into());
            } else {
                response.push_not_found(blob_id);
            }
        }

        Ok(response)
    }

    async fn blob_lookup(&self, request: BlobLookupRequest) -> trc::Result<BlobLookupResponse> {
        let mut type_names = Vec::with_capacity(request.type_names.len());
        for type_name in request.type_names {
            let MaybeInvalid::Value(type_name) = type_name else {
                return Err(trc::JmapEvent::UnknownDataType.into_err());
            };
            if !type_names.contains(&type_name) {
                type_names.push(type_name);
            }
        }
        let req_account_id = request.account_id.document_id();
        let mut response = BlobLookupResponse {
            account_id: request.account_id,
            list: Vec::with_capacity(request.ids.len()),
            not_found: vec![],
        };

        for id in request.ids.into_valid() {
            let mut matched_ids = type_names
                .iter()
                .map(|type_name| (*type_name, Vec::new()))
                .collect::<VecMap<_, _>>();

            match &id.class {
                BlobClass::Linked {
                    account_id,
                    collection,
                    document_id,
                } if *account_id == req_account_id
                    && self
                        .store()
                        .blob_has_access(&id.hash, &id.class)
                        .await
                        .caused_by(trc::location!())? =>
                {
                    match Collection::from(*collection) {
                        Collection::Email => {
                            if let Some(data) = self
                                .store()
                                .get_value::<MessageData>(ValueKey::archive(
                                    req_account_id,
                                    Collection::Email,
                                    *document_id,
                                ))
                                .await?
                            {
                                if let Some(ids) = matched_ids.get_mut(&DataType::Email) {
                                    ids.push(Id::from_parts(data.thread_id, *document_id));
                                }
                                if let Some(ids) = matched_ids.get_mut(&DataType::Thread) {
                                    ids.push(Id::from(data.thread_id));
                                }
                                if let Some(ids) = matched_ids.get_mut(&DataType::Mailbox) {
                                    ids.extend(data.mailboxes.iter().map(|m| {
                                        debug_assert!(m.uid != 0);
                                        Id::from(m.mailbox_id)
                                    }));
                                }
                            }
                        }
                        collection => {
                            if let Ok(data_type) = DataType::try_from(collection)
                                && let Some(ids) = matched_ids.get_mut(&data_type)
                            {
                                ids.push(Id::from(*document_id));
                            }
                        }
                    }
                }
                BlobClass::Embedded {
                    account_id,
                    collection,
                    document_id,
                } if *account_id == req_account_id
                    && self
                        .embedded_blob(&id)
                        .await
                        .caused_by(trc::location!())?
                        .is_some() =>
                {
                    if let Ok(data_type) = DataType::try_from(Collection::from(*collection))
                        && let Some(ids) = matched_ids.get_mut(&data_type)
                    {
                        ids.push(Id::from(*document_id));
                    }
                }
                BlobClass::Reserved { account_id, .. } if *account_id == req_account_id => {}
                _ => {
                    response.not_found.push(id);
                    continue;
                }
            }

            response.list.push(BlobInfo { id, matched_ids });
        }

        Ok(response)
    }
}
