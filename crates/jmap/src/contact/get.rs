/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::changes::state::JmapCacheState;
use calcard::jscontact::{JSContactProperty, JSContactValue};
use common::{Server, auth::AccessToken};
use groupware::{cache::GroupwareCache, contact::ContactCard};
use jmap_proto::{
    method::get::{GetRequest, GetResponse},
    object::contact,
    request::IntoValid,
};
use jmap_tools::{Map, Value};
use store::roaring::RoaringBitmap;
use trc::AddContext;
use types::{
    acl::Acl,
    blob::BlobId,
    collection::{Collection, SyncCollection},
    id::Id,
};

pub trait ContactCardGet: Sync + Send {
    fn contact_card_get(
        &self,
        request: GetRequest<contact::ContactCard>,
        access_token: &AccessToken,
    ) -> impl Future<Output = trc::Result<GetResponse<contact::ContactCard>>> + Send;
}

impl ContactCardGet for Server {
    async fn contact_card_get(
        &self,
        mut request: GetRequest<contact::ContactCard>,
        access_token: &AccessToken,
    ) -> trc::Result<GetResponse<contact::ContactCard>> {
        let ids = request.unwrap_ids(self.core.jmap.get_max_objects)?;
        let return_all_properties = request.properties.is_none();
        let properties =
            request.unwrap_properties(&[JSContactProperty::Id, JSContactProperty::AddressBookIds]);
        let account_id = request.account_id.document_id();
        let cache = self
            .fetch_dav_resources(access_token, account_id, SyncCollection::AddressBook)
            .await?;
        let contact_ids = if access_token.is_member(account_id) {
            cache.document_ids(false).collect::<RoaringBitmap>()
        } else {
            cache.shared_containers(access_token, [Acl::ReadItems], true)
        };
        let ids = if let Some(ids) = ids {
            ids
        } else {
            contact_ids
                .iter()
                .take(self.core.jmap.get_max_objects)
                .map(Into::into)
                .collect::<Vec<_>>()
        };
        let mut response = GetResponse {
            account_id: request.account_id.into(),
            state: cache.get_state(false).into(),
            list: Vec::with_capacity(ids.len()),
            not_found: vec![],
        };
        let return_id = return_all_properties || properties.contains(&JSContactProperty::Id);
        let return_address_book_ids =
            return_all_properties || properties.contains(&JSContactProperty::AddressBookIds);

        for id in ids {
            // Obtain the contact object
            let document_id = id.document_id();
            if !contact_ids.contains(document_id) {
                response.not_found.push(id);
                continue;
            }

            let _contact = if let Some(contact) = self
                .get_archive(account_id, Collection::ContactCard, document_id)
                .await?
            {
                contact
            } else {
                response.not_found.push(id);
                continue;
            };

            let contact = _contact
                .deserialize::<ContactCard>()
                .caused_by(trc::location!())?;

            let mut result = if return_all_properties {
                contact
                    .card
                    .into_jscontact::<Id, BlobId>()
                    .into_inner()
                    .into_object()
                    .unwrap()
            } else {
                Map::from_iter(
                    contact
                        .card
                        .into_jscontact::<Id, BlobId>()
                        .into_inner()
                        .into_expanded_object()
                        .filter(|(k, _)| k.as_property().is_some_and(|p| properties.contains(p))),
                )
            };

            if return_id {
                result.insert_unchecked(
                    JSContactProperty::Id,
                    Value::Element(JSContactValue::Id(id)),
                );
            }

            if return_address_book_ids {
                let mut obj = Map::with_capacity(contact.names.len());
                for id in contact.names.iter() {
                    obj.insert_unchecked(JSContactProperty::IdValue(Id::from(id.parent_id)), true);
                }
                result.insert_unchecked(JSContactProperty::AddressBookIds, Value::Object(obj));
            }

            response.list.push(result.into());
        }

        Ok(response)
    }
}
