/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::blob::download::BlobDownload;
use calcard::vcard::VCard;
use common::{Server, auth::AccessToken};
use jmap_proto::{
    method::parse::{ParseRequest, ParseResponse},
    object::contact::ContactCard,
    request::IntoValid,
};
use types::{blob::BlobId, id::Id};
use utils::map::vec_map::VecMap;

pub trait ContactCardParse: Sync + Send {
    fn contact_card_parse(
        &self,
        request: ParseRequest<ContactCard>,
        access_token: &AccessToken,
    ) -> impl Future<Output = trc::Result<ParseResponse<ContactCard>>> + Send;
}

impl ContactCardParse for Server {
    async fn contact_card_parse(
        &self,
        request: ParseRequest<ContactCard>,
        access_token: &AccessToken,
    ) -> trc::Result<ParseResponse<ContactCard>> {
        if request.blob_ids.len() > self.core.jmap.contact_parse_max_items {
            return Err(trc::JmapEvent::RequestTooLarge.into_err());
        }
        let return_all_properties = request.properties.is_none();
        let properties = request
            .properties
            .map(|v| v.into_valid().collect::<Vec<_>>())
            .unwrap_or_default();

        let mut response = ParseResponse {
            account_id: request.account_id,
            parsed: VecMap::with_capacity(request.blob_ids.len()),
            not_parsable: vec![],
            not_found: vec![],
        };

        for blob_id in request.blob_ids.into_valid() {
            // Fetch raw message to parse
            let raw_vcard = match self.blob_download(&blob_id, access_token).await? {
                Some(raw_vcard) => raw_vcard,
                None => {
                    response.not_found.push(blob_id);
                    continue;
                }
            };
            let Ok(vcard) = VCard::parse(std::str::from_utf8(&raw_vcard).unwrap_or_default())
            else {
                response.not_parsable.push(blob_id);
                continue;
            };
            let mut js_contact = vcard.into_jscontact::<Id, BlobId>();

            if !return_all_properties {
                js_contact
                    .0
                    .as_object_mut()
                    .unwrap()
                    .as_mut_vec()
                    .retain(|(k, _)| k.as_property().is_some_and(|k| properties.contains(k)));
            }

            response.parsed.append(blob_id, js_contact.into_inner());
        }

        Ok(response)
    }
}
