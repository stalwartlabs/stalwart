/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{changes::state::JmapCacheState, contact::set::ContactCardSet};
use common::{Server, auth::AccessToken};
use groupware::{cache::GroupwareCache, contact::ContactCard};
use http_proto::HttpSessionData;
use jmap_proto::{
    error::set::SetError,
    method::{
        copy::{CopyRequest, CopyResponse},
        set::SetRequest,
    },
    object::contact,
    request::{
        Call, IntoValid, MaybeInvalid, RequestMethod, SetRequestMethod,
        method::{MethodFunction, MethodName, MethodObject},
        reference::MaybeResultReference,
    },
    types::state::State,
};
use store::{ValueKey, roaring::RoaringBitmap, write::{AlignedBytes, Archive, BatchBuilder}};
use trc::AddContext;
use types::{
    acl::Acl,
    collection::{Collection, SyncCollection},
};
use utils::map::vec_map::VecMap;

pub trait JmapContactCardCopy: Sync + Send {
    fn contact_card_copy<'x>(
        &self,
        request: CopyRequest<'x, contact::ContactCard>,
        access_token: &AccessToken,
        next_call: &mut Option<Call<RequestMethod<'x>>>,
        session: &HttpSessionData,
    ) -> impl Future<Output = trc::Result<CopyResponse<contact::ContactCard>>> + Send;
}

impl JmapContactCardCopy for Server {
    async fn contact_card_copy<'x>(
        &self,
        request: CopyRequest<'x, contact::ContactCard>,
        access_token: &AccessToken,
        next_call: &mut Option<Call<RequestMethod<'x>>>,
        _session: &HttpSessionData,
    ) -> trc::Result<CopyResponse<contact::ContactCard>> {
        let account_id = request.account_id.document_id();
        let from_account_id = request.from_account_id.document_id();

        if account_id == from_account_id {
            return Err(trc::JmapEvent::InvalidArguments
                .into_err()
                .details("From accountId is equal to fromAccountId"));
        }
        let cache = self
            .fetch_dav_resources(access_token, account_id, SyncCollection::AddressBook)
            .await
            .caused_by(trc::location!())?;
        let old_state = cache.assert_state(false, &request.if_in_state)?;
        let mut response = CopyResponse {
            from_account_id: request.from_account_id,
            account_id: request.account_id,
            new_state: old_state.clone(),
            old_state,
            created: VecMap::with_capacity(request.create.len()),
            not_created: VecMap::new(),
        };

        let from_cache = self
            .fetch_dav_resources(access_token, from_account_id, SyncCollection::AddressBook)
            .await
            .caused_by(trc::location!())?;
        let from_contact_ids = if access_token.is_member(from_account_id) {
            from_cache.document_ids(false).collect::<RoaringBitmap>()
        } else {
            from_cache.shared_items(access_token, [Acl::ReadItems], true)
        };

        let can_add_address_books = if access_token.is_shared(account_id) {
            cache
                .shared_containers(access_token, [Acl::AddItems], true)
                .into()
        } else {
            None
        };
        let on_success_delete = request.on_success_destroy_original.unwrap_or(false);
        let mut destroy_ids = Vec::new();

        // Obtain quota
        let mut batch = BatchBuilder::new();

        'create: for (id, create) in request.create.into_valid() {
            let from_contact_id = id.document_id();
            if !from_contact_ids.contains(from_contact_id) {
                response.not_created.append(
                    id,
                    SetError::not_found().with_description(format!(
                        "Item {} not found in account {}.",
                        id, response.from_account_id
                    )),
                );
                continue;
            }

            let Some(_contact) = self
                .store()
                .get_value::<Archive<AlignedBytes>>(ValueKey::archive(
                    from_account_id,
                    Collection::ContactCard,
                    from_contact_id,
                ))
                .await?
            else {
                response.not_created.append(
                    id,
                    SetError::not_found().with_description(format!(
                        "Item {} not found in account {}.",
                        id, response.from_account_id
                    )),
                );
                continue;
            };

            let contact = _contact
                .deserialize::<ContactCard>()
                .caused_by(trc::location!())?;

            match self
                .create_contact_card(
                    &cache,
                    &mut batch,
                    access_token,
                    account_id,
                    &can_add_address_books,
                    contact.card.into_jscontact(),
                    create,
                )
                .await?
            {
                Ok(document_id) => {
                    response.created(id, document_id);

                    // Add to destroy list
                    if on_success_delete {
                        destroy_ids.push(MaybeInvalid::Value(id));
                    }
                }
                Err(err) => {
                    response.not_created.append(id, err);
                    continue 'create;
                }
            }
        }

        // Write changes
        if !batch.is_empty() {
            let change_id = self
                .commit_batch(batch)
                .await
                .and_then(|ids| ids.last_change_id(account_id))
                .caused_by(trc::location!())?;

            response.new_state = State::Exact(change_id);
        }

        // Destroy ids
        if on_success_delete && !destroy_ids.is_empty() {
            *next_call = Call {
                id: String::new(),
                name: MethodName::new(MethodObject::ContactCard, MethodFunction::Set),
                method: RequestMethod::Set(SetRequestMethod::ContactCard(SetRequest {
                    account_id: request.from_account_id,
                    if_in_state: request.destroy_from_if_in_state,
                    create: None,
                    update: None,
                    destroy: MaybeResultReference::Value(destroy_ids).into(),
                    arguments: Default::default(),
                })),
            }
            .into();
        }

        Ok(response)
    }
}
