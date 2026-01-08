/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::download::BlobDownload;
use common::{Server, auth::AccessToken};
use email::message::metadata::MessageData;
use jmap_proto::{
    method::{
        get::{GetRequest, GetResponse},
        lookup::{BlobInfo, BlobLookupRequest, BlobLookupResponse},
    },
    object::blob::{Blob, BlobProperty, BlobValue, DataProperty, DigestProperty},
    request::{IntoValid, MaybeInvalid},
};
use jmap_tools::{Map, Value};
use mail_builder::encoders::base64::base64_encode;
use sha1::{Digest, Sha1};
use sha2::{Sha256, Sha512};
use store::{ValueKey, write::{AlignedBytes, Archive}};
use std::future::Future;
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
        let ids = request
            .unwrap_ids(self.core.jmap.get_max_objects)?
            .unwrap_or_default();
        let properties = request.unwrap_properties(&[
            BlobProperty::Id,
            BlobProperty::Data(DataProperty::Default),
            BlobProperty::Size,
        ]);
        let mut response = GetResponse {
            account_id: request.account_id.into(),
            state: None,
            list: Vec::with_capacity(ids.len()),
            not_found: vec![],
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
                                    base64_encode(&hasher.finalize()[..]).unwrap_or_default(),
                                )
                                .unwrap()
                            }
                            DigestProperty::Sha256 => {
                                let mut hasher = Sha256::new();
                                hasher.update(bytes_range);
                                String::from_utf8(
                                    base64_encode(&hasher.finalize()[..]).unwrap_or_default(),
                                )
                                .unwrap()
                            }
                            DigestProperty::Sha512 => {
                                let mut hasher = Sha512::new();
                                hasher.update(bytes_range);
                                String::from_utf8(
                                    base64_encode(&hasher.finalize()[..]).unwrap_or_default(),
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
                            DataProperty::AsBase64 => {
                                String::from_utf8(base64_encode(bytes_range).unwrap_or_default())
                                    .unwrap()
                                    .into()
                            }
                            DataProperty::Default => match std::str::from_utf8(bytes_range) {
                                Ok(text) => {
                                    property = BlobProperty::Data(DataProperty::AsText);
                                    text.to_string().into()
                                }
                                Err(_) => {
                                    property = BlobProperty::Data(DataProperty::AsBase64);
                                    blob.insert_unchecked(BlobProperty::IsEncodingProblem, true);
                                    String::from_utf8(
                                        base64_encode(bytes_range).unwrap_or_default(),
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
                response.not_found.push(blob_id);
            }
        }

        Ok(response)
    }

    async fn blob_lookup(&self, request: BlobLookupRequest) -> trc::Result<BlobLookupResponse> {
        let mut include_email = false;
        let mut include_mailbox = false;
        let mut include_thread = false;

        let type_names = request
            .type_names
            .into_iter()
            .map(|tn| match tn {
                MaybeInvalid::Value(value) => {
                    match &value {
                        DataType::Email => {
                            include_email = true;
                        }
                        DataType::Mailbox => {
                            include_mailbox = true;
                        }
                        DataType::Thread => {
                            include_thread = true;
                        }
                        _ => (),
                    }

                    Ok(value)
                }
                MaybeInvalid::Invalid(_) => Err(trc::JmapEvent::UnknownDataType.into_err()),
            })
            .collect::<Result<Vec<_>, _>>()?;
        let req_account_id = request.account_id.document_id();
        let mut response = BlobLookupResponse {
            account_id: request.account_id,
            list: Vec::with_capacity(request.ids.len()),
            not_found: vec![],
        };

        for id in request.ids.into_valid() {
            let mut matched_ids = VecMap::new();

            match &id.class {
                BlobClass::Linked {
                    account_id,
                    collection,
                    document_id,
                } if *account_id == req_account_id => {
                    let collection = Collection::from(*collection);
                    if collection == Collection::Email {
                        if let Some(data_) = self
                            .store()
                            .get_value::<Archive<AlignedBytes>>(ValueKey::archive(
                                req_account_id,
                                Collection::Email,
                                *document_id,
                            ))
                            .await?
                        {
                            let data = data_
                                .unarchive::<MessageData>()
                                .caused_by(trc::location!())?;
                            if include_email {
                                matched_ids.append(
                                    DataType::Email,
                                    vec![Id::from_parts(u32::from(data.thread_id), *document_id)],
                                );
                            }
                            if include_thread {
                                matched_ids.append(
                                    DataType::Thread,
                                    vec![Id::from(u32::from(data.thread_id))],
                                );
                            }
                            if include_mailbox {
                                matched_ids.append(
                                    DataType::Mailbox,
                                    data.mailboxes
                                        .iter()
                                        .map(|m| {
                                            debug_assert!(m.uid != 0);
                                            Id::from(u32::from(m.mailbox_id))
                                        })
                                        .collect::<Vec<_>>(),
                                );
                            }
                        }
                    } else {
                        match DataType::try_from(collection) {
                            Ok(data_type) if type_names.contains(&data_type) => {
                                matched_ids.append(data_type, vec![Id::from(*document_id)]);
                            }
                            _ => (),
                        }
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
