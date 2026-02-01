/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::BlobStore;
use registry::schema::structs;
use s3::{Bucket, Region, creds::Credentials};
use std::{fmt::Display, io::Write, ops::Range, sync::Arc, time::Duration};
use utils::codec::base32_custom::Base32Writer;

pub struct S3Store {
    bucket: Box<Bucket>,
    prefix: Option<String>,
    max_retries: u32,
}

impl S3Store {
    pub async fn open(config: structs::S3Store) -> Result<BlobStore, String> {
        // Obtain region and endpoint from config
        let region = match config.region {
            structs::S3StoreRegion::UsEast1 => Region::UsEast1,
            structs::S3StoreRegion::UsEast2 => Region::UsEast2,
            structs::S3StoreRegion::UsWest1 => Region::UsWest1,
            structs::S3StoreRegion::UsWest2 => Region::UsWest2,
            structs::S3StoreRegion::CaCentral1 => Region::CaCentral1,
            structs::S3StoreRegion::AfSouth1 => Region::AfSouth1,
            structs::S3StoreRegion::ApEast1 => Region::ApEast1,
            structs::S3StoreRegion::ApSouth1 => Region::ApSouth1,
            structs::S3StoreRegion::ApNortheast1 => Region::ApNortheast1,
            structs::S3StoreRegion::ApNortheast2 => Region::ApNortheast2,
            structs::S3StoreRegion::ApNortheast3 => Region::ApNortheast3,
            structs::S3StoreRegion::ApSoutheast1 => Region::ApSoutheast1,
            structs::S3StoreRegion::ApSoutheast2 => Region::ApSoutheast2,
            structs::S3StoreRegion::CnNorth1 => Region::CnNorth1,
            structs::S3StoreRegion::CnNorthwest1 => Region::CnNorthwest1,
            structs::S3StoreRegion::EuNorth1 => Region::EuNorth1,
            structs::S3StoreRegion::EuCentral1 => Region::EuCentral1,
            structs::S3StoreRegion::EuCentral2 => Region::EuCentral2,
            structs::S3StoreRegion::EuWest1 => Region::EuWest1,
            structs::S3StoreRegion::EuWest2 => Region::EuWest2,
            structs::S3StoreRegion::EuWest3 => Region::EuWest3,
            structs::S3StoreRegion::IlCentral1 => Region::IlCentral1,
            structs::S3StoreRegion::MeSouth1 => Region::MeSouth1,
            structs::S3StoreRegion::SaEast1 => Region::SaEast1,
            structs::S3StoreRegion::DoNyc3 => Region::DoNyc3,
            structs::S3StoreRegion::DoAms3 => Region::DoAms3,
            structs::S3StoreRegion::DoSgp1 => Region::DoSgp1,
            structs::S3StoreRegion::DoFra1 => Region::DoFra1,
            structs::S3StoreRegion::Yandex => Region::Yandex,
            structs::S3StoreRegion::WaUsEast1 => Region::WaUsEast1,
            structs::S3StoreRegion::WaUsEast2 => Region::WaUsEast2,
            structs::S3StoreRegion::WaUsCentral1 => Region::WaUsCentral1,
            structs::S3StoreRegion::WaUsWest1 => Region::WaUsWest1,
            structs::S3StoreRegion::WaCaCentral1 => Region::WaCaCentral1,
            structs::S3StoreRegion::WaEuCentral1 => Region::WaEuCentral1,
            structs::S3StoreRegion::WaEuCentral2 => Region::WaEuCentral2,
            structs::S3StoreRegion::WaEuWest1 => Region::WaEuWest1,
            structs::S3StoreRegion::WaEuWest2 => Region::WaEuWest2,
            structs::S3StoreRegion::WaApNortheast1 => Region::WaApNortheast1,
            structs::S3StoreRegion::WaApNortheast2 => Region::WaApNortheast2,
            structs::S3StoreRegion::WaApSoutheast1 => Region::WaApSoutheast1,
            structs::S3StoreRegion::WaApSoutheast2 => Region::WaApSoutheast2,
            structs::S3StoreRegion::Custom(custom) => Region::Custom {
                region: custom.custom_region,
                endpoint: custom.custom_endpoint,
            },
        };
        let credentials = Credentials::new(
            config.access_key.as_deref(),
            config.secret_key.as_deref(),
            config.security_token.as_deref(),
            config.session_token.as_deref(),
            config.profile.as_deref(),
        )
        .map_err(|err| format!("Failed to create credentials: {err:?}"))?;

        Ok(BlobStore::S3(Arc::new(S3Store {
            bucket: Bucket::new(&config.bucket, region, credentials)
                .map_err(|err| format!("Failed to create bucket: {err:?}"))?
                .with_path_style()
                /*.set_dangereous_config(allow_invalid, allow_invalid)
                .map_err(|err| {
                    format!("Failed to create bucket: {err:?}")
                })
                ?*/
                .with_request_timeout(config.timeout.into_inner())
                .map_err(|err| format!("Failed to create bucket: {err:?}"))?,
            max_retries: config.max_retries as u32,
            prefix: config.key_prefix,
        })))
    }

    pub(crate) async fn get_blob(
        &self,
        key: &[u8],
        range: Range<usize>,
    ) -> trc::Result<Option<Vec<u8>>> {
        let path = self.build_key(key);
        let mut retries_left = self.max_retries;

        loop {
            let response = if range.start != 0 || range.end != usize::MAX {
                self.bucket
                    .get_object_range(
                        &path,
                        range.start as u64,
                        Some(range.end.saturating_sub(1) as u64),
                    )
                    .await
            } else {
                self.bucket.get_object(&path).await
            }
            .map_err(into_error)?;

            match response.status_code() {
                200..=299 => return Ok(Some(response.to_vec())),
                404 => return Ok(None),
                500..=599 if retries_left > 0 => {
                    // wait backoff
                    tokio::time::sleep(Duration::from_secs(
                        1 << (self.max_retries - retries_left).min(6),
                    ))
                    .await;

                    retries_left -= 1;
                }
                code => {
                    return Err(trc::StoreEvent::S3Error
                        .reason(String::from_utf8_lossy(response.as_slice()))
                        .ctx(trc::Key::Code, code));
                }
            }
        }
    }

    pub(crate) async fn put_blob(&self, key: &[u8], data: &[u8]) -> trc::Result<()> {
        let mut retries_left = self.max_retries;

        loop {
            let response = self
                .bucket
                .put_object(self.build_key(key), data)
                .await
                .map_err(into_error)?;

            match response.status_code() {
                200..=299 => return Ok(()),
                500..=599 if retries_left > 0 => {
                    // wait backoff
                    tokio::time::sleep(Duration::from_secs(
                        1 << (self.max_retries - retries_left).min(6),
                    ))
                    .await;

                    retries_left -= 1;
                }
                code => {
                    return Err(trc::StoreEvent::S3Error
                        .reason(String::from_utf8_lossy(response.as_slice()))
                        .ctx(trc::Key::Code, code));
                }
            }
        }
    }

    pub(crate) async fn delete_blob(&self, key: &[u8]) -> trc::Result<bool> {
        let mut retries_left = self.max_retries;

        loop {
            let response = self
                .bucket
                .delete_object(self.build_key(key))
                .await
                .map_err(into_error)?;

            match response.status_code() {
                200..=299 => return Ok(true),
                404 => return Ok(false),
                500..=599 if retries_left > 0 => {
                    // wait backoff
                    tokio::time::sleep(Duration::from_secs(
                        1 << (self.max_retries - retries_left).min(6),
                    ))
                    .await;

                    retries_left -= 1;
                }
                code => {
                    return Err(trc::StoreEvent::S3Error
                        .reason(String::from_utf8_lossy(response.as_slice()))
                        .ctx(trc::Key::Code, code));
                }
            }
        }
    }

    fn build_key(&self, key: &[u8]) -> String {
        if let Some(prefix) = &self.prefix {
            let mut writer =
                Base32Writer::with_raw_capacity(prefix.len() + (key.len().div_ceil(4) * 5));
            writer.push_string(prefix);
            writer.write_all(key).unwrap();
            writer.finalize()
        } else {
            Base32Writer::from_bytes(key).finalize()
        }
    }
}

#[inline(always)]
fn into_error(err: impl Display) -> trc::Error {
    trc::StoreEvent::S3Error.reason(err)
}
