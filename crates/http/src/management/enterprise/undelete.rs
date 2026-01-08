/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: LicenseRef-SEL
 *
 * This file is subject to the Stalwart Enterprise License Agreement (SEL) and
 * is NOT open source software.
 *
 */

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use common::{Server, enterprise::undelete::DeletedItemType};
use directory::backend::internal::manage::ManageDirectory;
use email::{
    mailbox::INBOX_ID,
    message::ingest::{EmailIngest, IngestEmail, IngestSource},
};
use http_proto::{request::decode_path_element, *};
use hyper::Method;
use mail_parser::{DateTime, MessageParser};
use serde_json::json;
use std::future::Future;
use std::str::FromStr;
use store::write::{BatchBuilder, BlobLink, BlobOp};
use trc::AddContext;
use types::{blob_hash::BlobHash, collection::Collection};
use utils::url_params::UrlParams;

#[derive(serde::Deserialize, serde::Serialize, Debug)]
pub struct UndeleteRequest<H, C, T> {
    pub hash: H,
    pub collection: C,
    #[serde(rename = "restoreTime")]
    pub time: T,
    #[serde(rename = "cancelDeletion")]
    #[serde(default)]
    pub cancel_deletion: Option<T>,
}

#[derive(serde::Serialize, serde::Deserialize, PartialEq, Eq, Debug)]
#[serde(tag = "type")]
#[serde(rename_all = "camelCase")]
pub enum UndeleteResponse {
    Success,
    NotFound,
    Error { reason: String },
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct DeletedBlobResponse {
    pub hash: String,
    pub size: u32,
    #[serde(rename = "deletedAt")]
    pub deleted_at: String,
    #[serde(rename = "expiresAt")]
    pub expires_at: String,
    pub item: DeletedItemResponse,
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
#[serde(tag = "type")]
#[serde(rename_all = "camelCase")]
pub enum DeletedItemResponse {
    Email {
        from: Box<str>,
        subject: Box<str>,
        received_at: String,
    },
    FileNode {
        name: Box<str>,
    },
    CalendarEvent {
        title: Box<str>,
        start_time: String,
    },
    ContactCard {
        name: Box<str>,
    },
    SieveScript {
        name: Box<str>,
    },
}

pub trait UndeleteApi: Sync + Send {
    fn handle_undelete_api_request(
        &self,
        req: &HttpRequest,
        path: Vec<&str>,
        body: Option<Vec<u8>>,
        session: &HttpSessionData,
    ) -> impl Future<Output = trc::Result<HttpResponse>> + Send;
}

impl UndeleteApi for Server {
    async fn handle_undelete_api_request(
        &self,
        req: &HttpRequest,
        path: Vec<&str>,
        body: Option<Vec<u8>>,
        session: &HttpSessionData,
    ) -> trc::Result<HttpResponse> {
        match (path.get(2).copied(), req.method()) {
            (Some(account_name), &Method::GET) => {
                let account_name = decode_path_element(account_name);
                let account_id = self
                    .core
                    .storage
                    .data
                    .get_principal_id(account_name.as_ref())
                    .await?
                    .ok_or_else(|| trc::ResourceEvent::NotFound.into_err())?;
                let mut deleted = self.core.list_deleted(account_id).await?;

                let params = UrlParams::new(req.uri().query());
                let limit = params.parse::<usize>("limit").unwrap_or_default();
                let mut offset = params
                    .parse::<usize>("page")
                    .unwrap_or_default()
                    .saturating_sub(1)
                    * limit;

                // Sort ascending by deleted_at
                let total = deleted.len();
                deleted.sort_by(|a, b| a.item.deleted_at.cmp(&b.item.deleted_at));
                let mut results = Vec::with_capacity(if limit > 0 { limit } else { total });

                for blob in deleted {
                    if offset == 0 {
                        results.push(DeletedBlobResponse {
                            hash: URL_SAFE_NO_PAD.encode(blob.hash.as_slice()),
                            size: blob.item.size,
                            deleted_at: DateTime::from_timestamp(blob.item.deleted_at as i64)
                                .to_rfc3339(),
                            expires_at: DateTime::from_timestamp(blob.expires_at as i64)
                                .to_rfc3339(),
                            item: match blob.item.typ {
                                DeletedItemType::Email {
                                    from,
                                    subject,
                                    received_at,
                                } => DeletedItemResponse::Email {
                                    from,
                                    subject,
                                    received_at: DateTime::from_timestamp(received_at as i64)
                                        .to_rfc3339(),
                                },
                                DeletedItemType::FileNode { name } => {
                                    DeletedItemResponse::FileNode { name }
                                }
                                DeletedItemType::CalendarEvent { title, start_time } => {
                                    DeletedItemResponse::CalendarEvent {
                                        title,
                                        start_time: DateTime::from_timestamp(start_time as i64)
                                            .to_rfc3339(),
                                    }
                                }
                                DeletedItemType::ContactCard { name } => {
                                    DeletedItemResponse::ContactCard { name }
                                }
                                DeletedItemType::SieveScript { name } => {
                                    DeletedItemResponse::SieveScript { name }
                                }
                            },
                        });
                        if results.len() == limit {
                            break;
                        }
                    } else {
                        offset -= 1;
                    }
                }

                Ok(JsonResponse::new(json!({
                        "data":{
                            "items": results,
                            "total": total,
                        },
                }))
                .into_http_response())
            }
            (Some(account_name), &Method::POST) => {
                let account_name = decode_path_element(account_name);
                let account_id = self
                    .core
                    .storage
                    .data
                    .get_principal_id(account_name.as_ref())
                    .await?
                    .ok_or_else(|| trc::ResourceEvent::NotFound.into_err())?;

                let requests: Vec<UndeleteRequest<BlobHash, Collection, u64>> =
                    match serde_json::from_slice::<
                        Option<Vec<UndeleteRequest<String, String, String>>>,
                    >(body.as_deref().unwrap_or_default())
                    {
                        Ok(Some(requests)) => requests
                            .into_iter()
                            .map(|request| {
                                UndeleteRequest {
                                    hash: BlobHash::try_from_hash_slice(
                                        URL_SAFE_NO_PAD
                                            .decode(request.hash.as_bytes())
                                            .ok()?
                                            .as_slice(),
                                    )
                                    .ok()?,
                                    collection: Collection::from_str(request.collection.as_str())
                                        .ok()?,
                                    time: DateTime::parse_rfc3339(request.time.as_str())?
                                        .to_timestamp()
                                        as u64,
                                    cancel_deletion: if let Some(cancel_deletion) =
                                        request.cancel_deletion
                                    {
                                        (DateTime::parse_rfc3339(cancel_deletion.as_str())?
                                            .to_timestamp()
                                            as u64)
                                            .into()
                                    } else {
                                        None
                                    },
                                }
                                .into()
                            })
                            .collect::<Option<Vec<_>>>()
                            .ok_or_else(|| trc::ResourceEvent::BadParameters.into_err())?,
                        Ok(None) => {
                            let deleted = self.core.list_deleted(account_id).await?;
                            let mut results = Vec::with_capacity(deleted.len());
                            for blob in deleted {
                                results.push(UndeleteRequest {
                                    hash: blob.hash,
                                    collection: match blob.item.typ {
                                        DeletedItemType::Email { .. } => Collection::Email,
                                        DeletedItemType::FileNode { .. } => Collection::FileNode,
                                        DeletedItemType::CalendarEvent { .. } => {
                                            Collection::CalendarEvent
                                        }
                                        DeletedItemType::ContactCard { .. } => {
                                            Collection::ContactCard
                                        }
                                        DeletedItemType::SieveScript { .. } => {
                                            Collection::SieveScript
                                        }
                                    },
                                    time: blob.item.deleted_at,
                                    cancel_deletion: blob.expires_at.into(),
                                });
                            }
                            results
                        }
                        Err(_) => {
                            return Err(trc::ResourceEvent::BadParameters.into_err());
                        }
                    };

                let access_token = self
                    .get_access_token(account_id)
                    .await
                    .caused_by(trc::location!())?;
                let mut results = Vec::with_capacity(requests.len());
                let mut batch = BatchBuilder::new();
                batch.with_account_id(account_id);
                for request in requests {
                    match request.collection {
                        Collection::Email => {
                            match self
                                .blob_store()
                                .get_blob(request.hash.as_slice(), 0..usize::MAX)
                                .await?
                            {
                                Some(bytes) => {
                                    match self
                                        .email_ingest(IngestEmail {
                                            raw_message: &bytes,
                                            message: MessageParser::new().parse(&bytes),
                                            blob_hash: Some(&request.hash),
                                            access_token: access_token.as_ref(),
                                            mailbox_ids: vec![INBOX_ID],
                                            keywords: vec![],
                                            received_at: request.time.into(),
                                            source: IngestSource::Restore,
                                            session_id: session.session_id,
                                        })
                                        .await
                                    {
                                        Ok(_) => {
                                            results.push(UndeleteResponse::Success);
                                            if let Some(cancel_deletion) = request.cancel_deletion {
                                                batch
                                                    .clear(BlobOp::Link {
                                                        hash: request.hash.clone(),
                                                        to: BlobLink::Temporary {
                                                            until: cancel_deletion,
                                                        },
                                                    })
                                                    .clear(BlobOp::Undelete {
                                                        hash: request.hash,
                                                        until: cancel_deletion,
                                                    });
                                            }
                                        }
                                        Err(mut err)
                                            if err.matches(trc::EventType::MessageIngest(
                                                trc::MessageIngestEvent::Error,
                                            )) =>
                                        {
                                            results.push(UndeleteResponse::Error {
                                                reason: err
                                                    .take_value(trc::Key::Reason)
                                                    .and_then(|v| v.into_string())
                                                    .unwrap()
                                                    .to_string(),
                                            });
                                        }
                                        Err(err) => {
                                            return Err(err.caused_by(trc::location!()));
                                        }
                                    }
                                }
                                None => {
                                    results.push(UndeleteResponse::NotFound);
                                }
                            }
                        }
                        _ => {
                            results.push(UndeleteResponse::Error {
                                reason: "Unsupported collection".to_string(),
                            });
                        }
                    }
                }

                // Commit batch
                if !batch.is_empty() {
                    self.core
                        .storage
                        .data
                        .write(batch.build_all())
                        .await
                        .caused_by(trc::location!())?;
                }

                Ok(JsonResponse::new(json!({
                    "data": results,
                }))
                .into_http_response())
            }
            _ => Err(trc::ResourceEvent::NotFound.into_err()),
        }
    }
}
