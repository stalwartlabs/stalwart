/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{api::acl::JmapRights, changes::state::JmapCacheState};
use common::{Server, auth::AccessToken, sharing::EffectiveAcl};
use groupware::{cache::GroupwareCache, contact::AddressBook};
use jmap_proto::{
    method::get::{GetRequest, GetResponse},
    object::addressbook::{self, AddressBookProperty, AddressBookValue},
};
use jmap_tools::{Map, Value};
use store::{ValueKey, roaring::RoaringBitmap, write::{AlignedBytes, Archive, ValueClass}};
use trc::AddContext;
use types::{
    acl::{Acl, AclGrant},
    collection::{Collection, SyncCollection},
    field::PrincipalField,
};

pub trait AddressBookGet: Sync + Send {
    fn address_book_get(
        &self,
        request: GetRequest<addressbook::AddressBook>,
        access_token: &AccessToken,
    ) -> impl Future<Output = trc::Result<GetResponse<addressbook::AddressBook>>> + Send;
}

impl AddressBookGet for Server {
    async fn address_book_get(
        &self,
        mut request: GetRequest<addressbook::AddressBook>,
        access_token: &AccessToken,
    ) -> trc::Result<GetResponse<addressbook::AddressBook>> {
        let ids = request.unwrap_ids(self.core.jmap.get_max_objects)?;
        let properties = request.unwrap_properties(&[
            AddressBookProperty::Id,
            AddressBookProperty::Name,
            AddressBookProperty::Description,
            AddressBookProperty::SortOrder,
            AddressBookProperty::IsDefault,
            AddressBookProperty::IsSubscribed,
            AddressBookProperty::MyRights,
        ]);
        let account_id = request.account_id.document_id();
        let cache = self
            .fetch_dav_resources(access_token, account_id, SyncCollection::AddressBook)
            .await?;
        let address_book_ids = if access_token.is_member(account_id) {
            cache.document_ids(true).collect::<RoaringBitmap>()
        } else {
            cache.shared_containers(access_token, [Acl::Read, Acl::ReadItems], true)
        };
        let default_address_book_id = self
            .store()
            .get_value::<u32>(ValueKey {
                account_id,
                collection: Collection::Principal.into(),
                document_id: 0,
                class: ValueClass::Property(PrincipalField::DefaultAddressBookId.into()),
            })
            .await
            .caused_by(trc::location!())?
            .or_else(|| {
                if address_book_ids.len() == 1 {
                    address_book_ids.iter().next()
                } else {
                    None
                }
            });

        let ids = if let Some(ids) = ids {
            ids
        } else {
            address_book_ids
                .iter()
                .take(self.core.jmap.get_max_objects)
                .map(Into::into)
                .collect::<Vec<_>>()
        };
        let mut response = GetResponse {
            account_id: request.account_id.into(),
            state: cache.get_state(true).into(),
            list: Vec::with_capacity(ids.len()),
            not_found: vec![],
        };

        for id in ids {
            // Obtain the address_book object
            let document_id = id.document_id();
            if !address_book_ids.contains(document_id) {
                response.not_found.push(id);
                continue;
            }
            let _address_book = if let Some(address_book) = self
                .store()
                .get_value::<Archive<AlignedBytes>>(ValueKey::archive(
                    account_id,
                    Collection::AddressBook,
                    document_id,
                ))
                .await?
            {
                address_book
            } else {
                response.not_found.push(id);
                continue;
            };
            let address_book = _address_book
                .unarchive::<AddressBook>()
                .caused_by(trc::location!())?;
            let mut result = Map::with_capacity(properties.len());
            for property in &properties {
                match property {
                    AddressBookProperty::Id => {
                        result.insert_unchecked(AddressBookProperty::Id, AddressBookValue::Id(id));
                    }
                    AddressBookProperty::Name => {
                        result.insert_unchecked(
                            AddressBookProperty::Name,
                            address_book.preferences(access_token.primary_id).name.to_string(),
                        );
                    }
                    AddressBookProperty::Description => {
                        result.insert_unchecked(
                            AddressBookProperty::Description,
                            address_book
                                .preferences(access_token.primary_id)
                                .description
                                .as_ref()
                                .map(|v| v.to_string()),
                        );
                    }
                    AddressBookProperty::SortOrder => {
                        result.insert_unchecked(
                            AddressBookProperty::SortOrder,
                            address_book
                                .preferences(access_token.primary_id)
                                .sort_order
                                .to_native(),
                        );
                    }
                    AddressBookProperty::IsDefault => {
                        result.insert_unchecked(
                            AddressBookProperty::IsDefault,
                            default_address_book_id == Some(document_id),
                        );
                    }
                    AddressBookProperty::IsSubscribed => {
                        result.insert_unchecked(
                            AddressBookProperty::IsSubscribed,
                            address_book
                                .subscribers
                                .iter()
                                .any(|account_id| *account_id == access_token.primary_id()),
                        );
                    }
                    AddressBookProperty::ShareWith => {
                        result.insert_unchecked(
                            AddressBookProperty::ShareWith,
                            JmapRights::share_with::<addressbook::AddressBook>(
                                account_id,
                                access_token,
                                &address_book
                                    .acls
                                    .iter()
                                    .map(AclGrant::from)
                                    .collect::<Vec<_>>(),
                            ),
                        );
                    }
                    AddressBookProperty::MyRights => {
                        result.insert_unchecked(
                            AddressBookProperty::MyRights,
                            if access_token.is_shared(account_id) {
                                JmapRights::rights::<addressbook::AddressBook>(
                                    address_book.acls.effective_acl(access_token),
                                )
                            } else {
                                JmapRights::all_rights::<addressbook::AddressBook>()
                            },
                        );
                    }
                    property => {
                        result.insert_unchecked(property.clone(), Value::Null);
                    }
                }
            }
            response.list.push(result.into());
        }

        Ok(response)
    }
}
