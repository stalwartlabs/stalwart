/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use azure_core::error::ErrorKind;
use azure_core::{ExponentialRetryOptions, RetryOptions, StatusCode};
use azure_storage::StorageCredentials;
use azure_storage_blobs::prelude::{ClientBuilder, ContainerClient};
use futures::stream::StreamExt;
use encodify::base32::STALWART;
use registry::schema::structs::{self};
use std::sync::Arc;
use std::{fmt::Display, ops::Range};

use crate::BlobStore;

pub struct AzureStore {
    client: ContainerClient,
    prefix: Option<String>,
}

impl AzureStore {
    pub async fn open(config: structs::AzureStore) -> Result<BlobStore, String> {
        let credentials = match (
            config.access_key.secret().await?.map(|v| v.into_owned()),
            config.sas_token.secret().await?.map(|v| v.into_owned()),
        ) {
            (Some(access_key), None) => {
                StorageCredentials::access_key(config.storage_account.clone(), access_key)
            }
            (None, Some(sas_token)) => match StorageCredentials::sas_token(sas_token) {
                Ok(cred) => cred,
                Err(err) => {
                    return Err(format!("Failed to create credentials: {err:?}"));
                }
            },
            _ => {
                return Err(concat!(
                    "Failed to create credentials: exactly one of ",
                    "'azure-access-key' and 'sas-token' must be specified"
                )
                .to_string());
            }
        };

        Ok(BlobStore::Azure(Arc::new(AzureStore {
            client: ClientBuilder::new(config.storage_account, credentials)
                .retry(RetryOptions::exponential(
                    ExponentialRetryOptions::default().max_retries(config.max_retries as u32 * 2),
                ))
                .container_client(config.container),
            prefix: config.key_prefix,
        })))
    }

    pub(crate) async fn get_blob(
        &self,
        key: &[u8],
        range: Range<usize>,
    ) -> trc::Result<Option<Vec<u8>>> {
        let blob_client = self.client.blob_client(self.build_key(key));

        let mut stream = blob_client.get();
        let mut buf = if range.end == usize::MAX {
            // Let's turn this into a proper RangeFrom.
            stream = stream.range(range.start..);
            // We don't know how big to expect the result to be.
            Vec::new()
        } else {
            stream = stream.range(range.clone());
            Vec::with_capacity(range.end - range.start)
        };
        let mut stream = stream.into_stream();

        while let Some(response) = stream.next().await {
            let err = match response {
                Ok(chunks) => {
                    let mut chunks = chunks.data;
                    let mut err = None;
                    while let Some(chunk) = chunks.next().await {
                        match chunk {
                            Ok(ref data) => {
                                buf.extend(data);
                            }
                            Err(e) => {
                                err = Some(e);
                                break;
                            }
                        }
                    }
                    err
                }
                Err(e) => Some(e),
            };

            if let Some(e) = err {
                return if matches!(
                    e.kind(),
                    ErrorKind::HttpResponse {
                        status: StatusCode::NotFound,
                        ..
                    }
                ) {
                    Ok(None)
                } else {
                    Err(trc::StoreEvent::AzureError.reason(e))
                };
            }
        }

        Ok(Some(buf))
    }

    pub(crate) async fn put_blob(&self, key: &[u8], data: &[u8]) -> trc::Result<()> {
        let blob_client = self.client.blob_client(self.build_key(key));

        // We unfortunately have to make a copy of `data`. This is because the Azure SDK wants to
        // coerce the body into a value of type azure_core::Body, which doesn't have a lifetime
        // parameter and so cannot hold any non-static references (directly or indirectly).
        let data = data.to_vec();

        blob_client
            .put_block_blob(data)
            .into_future()
            .await
            .map_err(into_error)?;

        Ok(())
    }

    pub(crate) async fn delete_blob(&self, key: &[u8]) -> trc::Result<bool> {
        let blob_client = self.client.blob_client(self.build_key(key));

        if let Err(e) = blob_client.delete().into_future().await {
            if matches!(
                e.kind(),
                ErrorKind::HttpResponse {
                    status: StatusCode::NotFound,
                    ..
                }
            ) {
                Ok(false)
            } else {
                Err(trc::StoreEvent::AzureError.reason(e))
            }
        } else {
            Ok(true)
        }
    }

    fn build_key(&self, key: &[u8]) -> String {
        if let Some(prefix) = &self.prefix {
            let mut out = String::with_capacity(prefix.len() + STALWART.encoded_len(key.len()));
            out.push_str(prefix);
            STALWART.encode_append(key, &mut out);
            out
        } else {
            STALWART.encode(key)
        }
    }
}

#[inline(always)]
fn into_error(err: impl Display) -> trc::Error {
    trc::StoreEvent::AzureError.reason(err)
}
