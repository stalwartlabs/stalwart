/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::blob::download::BlobDownload;
use common::{Server, auth::AccessToken};
use email::message::mdn::parse_mdn;
use jmap_proto::{
    method::mdn::{MdnParseRequest, MdnParseResponse},
    request::{MaybeInvalid, reference::MaybeIdReference},
};
use std::future::Future;
use utils::map::vec_map::VecMap;

pub trait MdnParse: Sync + Send {
    fn mdn_parse(
        &self,
        request: MdnParseRequest,
        access_token: &AccessToken,
    ) -> impl Future<Output = trc::Result<MdnParseResponse>> + Send;
}

impl MdnParse for Server {
    async fn mdn_parse(
        &self,
        request: MdnParseRequest,
        access_token: &AccessToken,
    ) -> trc::Result<MdnParseResponse> {
        if request.blob_ids.len() > self.core.jmap.mail_parse_max_items {
            return Err(trc::JmapEvent::RequestTooLarge.into_err());
        }

        let mut response = MdnParseResponse {
            account_id: request.account_id,
            parsed: VecMap::with_capacity(request.blob_ids.len()),
            not_parsable: vec![],
            not_found: vec![],
        };

        for blob_id in request.blob_ids {
            let blob_id = match blob_id {
                MaybeIdReference::Id(blob_id) => blob_id,
                MaybeIdReference::Invalid(id) | MaybeIdReference::Reference(id) => {
                    response.not_found.push(MaybeInvalid::Invalid(id));
                    continue;
                }
            };
            let Some(blob) = self.blob_download(&blob_id, access_token).await? else {
                response.not_found.push(MaybeInvalid::Value(blob_id));
                continue;
            };
            match parse_mdn(&blob) {
                Some(mdn) => response.parsed.append(blob_id, mdn),
                None => response.not_parsable.push(blob_id),
            }
        }

        Ok(response)
    }
}
