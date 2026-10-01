/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    api::metadata::{
        MetadataPatches, MetadataPreload, MetadataType, MetadataWriter, NewMetadata, ObjectMetadata,
    },
    changes::state::JmapCacheState,
    contact::set::{ContactCardSet, too_many_contacts},
};
use calcard::jscontact::JSContactProperty;
use common::{Server, auth::AccessToken};
use groupware::{cache::GroupwareCache, contact::ContactCardContent};
use http_proto::HttpSessionData;
use jmap_proto::{
    error::set::SetError,
    method::{
        copy::{CopyRequest, CopyResponse, CopySourceId},
        set::SetRequest,
    },
    object::contact,
    request::{
        Call, MaybeInvalid, RequestMethod, SetRequestMethod,
        capability::CapabilityIds,
        method::{MethodFunction, MethodName, MethodObject},
        reference::MaybeResultReference,
    },
    types::state::State,
};
use registry::schema::enums::StorageQuota;
use store::{
    ValueKey,
    roaring::RoaringBitmap,
    write::{Archive, ArchiveBytes, BatchBuilder, Slot},
};
use trc::AddContext;
use types::{
    acl::Acl,
    collection::{Collection, SyncCollection},
    field::ContactField,
    metadata::MetadataKinds,
};
use utils::map::vec_map::VecMap;

pub trait JmapContactCardCopy: Sync + Send {
    fn contact_card_copy<'x>(
        &self,
        request: CopyRequest<'x, contact::ContactCard>,
        access_token: &AccessToken,
        next_call: &mut Option<Call<RequestMethod<'x>>>,
        session: &HttpSessionData,
        using: CapabilityIds,
    ) -> impl Future<Output = trc::Result<CopyResponse<contact::ContactCard>>> + Send;
}

impl JmapContactCardCopy for Server {
    async fn contact_card_copy<'x>(
        &self,
        request: CopyRequest<'x, contact::ContactCard>,
        access_token: &AccessToken,
        next_call: &mut Option<Call<RequestMethod<'x>>>,
        _session: &HttpSessionData,
        using: CapabilityIds,
    ) -> trc::Result<CopyResponse<contact::ContactCard>> {
        let account_id = request.account_id.document_id();
        let from_account_id = request.from_account_id.document_id();
        let account = self.account(account_id).await.caused_by(trc::location!())?;

        if account_id == from_account_id {
            return Err(trc::JmapEvent::InvalidArguments
                .into_err()
                .details("From accountId is equal to fromAccountId"));
        }
        let metadata = ObjectMetadata::new(self, access_token, using, MetadataType::ContactCard);
        let sampled = metadata.viewer_change_id(self, account_id).await?;
        let cache = self
            .fetch_groupware_resources(
                access_token.account_id(),
                account_id,
                SyncCollection::AddressBook,
            )
            .await
            .caused_by(trc::location!())?;
        let old_state = sampled.assert_state(cache.get_state(false), &request.if_in_state)?;
        let mut response = CopyResponse {
            from_account_id: request.from_account_id,
            account_id: request.account_id,
            new_state: old_state.clone(),
            old_state,
            created: VecMap::with_capacity(request.create.len()),
            not_created: VecMap::new(),
        };

        let from_cache = self
            .fetch_groupware_resources(
                access_token.account_id(),
                from_account_id,
                SyncCollection::AddressBook,
            )
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
        let mut created_slots: Vec<(String, Slot)> = Vec::new();

        // Obtain quota
        let quota = self.object_quota_usage(&account, StorageQuota::MaxContactCards, || {
            cache.resources.count(false)
        });
        let mut batch = BatchBuilder::new();
        let viewer = metadata.viewer();
        let mut metadata_writer = MetadataWriter::new(metadata, account_id);
        let mut preload = MetadataPreload::default();
        for document_id in request
            .create
            .values()
            .filter_map(|create| create.source_id(JSContactProperty::Id))
            .map(|source_id| source_id.document_id())
            .filter(|document_id| from_contact_ids.contains(*document_id))
        {
            let kinds = from_cache
                .item_by_id(document_id)
                .map_or(MetadataKinds::NONE, |resource| resource.metadata_kinds());
            if viewer.is_some() || !kinds.is_empty() {
                preload.insert_source(document_id, kinds);
            }
        }
        metadata_writer
            .preload(self, from_account_id, preload)
            .await?;

        'create: for (create_id, mut create) in request.create {
            if !quota.has_room(created_slots.len()) {
                response.not_created.append(create_id, too_many_contacts());
                continue;
            }

            let source_id = match create.take_source_id(JSContactProperty::Id) {
                Ok(source_id) => source_id,
                Err(err) => {
                    response.not_created.append(create_id, err);
                    continue;
                }
            };
            let patches = match metadata_writer.extract(MetadataPatches::for_create(), &mut create)
            {
                Ok(patches) => patches,
                Err(err) => {
                    response.not_created.append(create_id, err);
                    continue;
                }
            };
            let from_contact_id = source_id.document_id();
            if !from_contact_ids.contains(from_contact_id) {
                response.not_created.append(
                    create_id,
                    SetError::not_found().with_description(format!(
                        "Item {} not found in account {}.",
                        source_id, response.from_account_id
                    )),
                );
                continue;
            }

            let Some(_contact) = self
                .store()
                .get_value::<Archive<ArchiveBytes>>(ValueKey::property(
                    from_account_id,
                    Collection::ContactCard,
                    from_contact_id,
                    ContactField::Content,
                ))
                .await?
            else {
                response.not_created.append(
                    create_id,
                    SetError::not_found().with_description(format!(
                        "Item {} not found in account {}.",
                        source_id, response.from_account_id
                    )),
                );
                continue;
            };

            let contact = _contact
                .deserialize::<ContactCardContent>()
                .caused_by(trc::location!())?;

            match self
                .create_contact_card(
                    &cache,
                    &mut batch,
                    access_token,
                    &account,
                    account_id,
                    &can_add_address_books,
                    contact.card.into_jscontact(),
                    create,
                    &mut metadata_writer,
                    Some(NewMetadata::Copy {
                        patches,
                        source_id: from_contact_id,
                    }),
                )
                .await?
            {
                Ok(document_id) => {
                    created_slots.push((create_id, document_id));

                    // Add to destroy list
                    if on_success_delete {
                        destroy_ids.push(MaybeInvalid::Value(source_id));
                    }
                }
                Err(err) => {
                    response.not_created.append(create_id, err);
                    continue 'create;
                }
            }
        }

        // Write changes
        if !batch.is_empty() {
            let assigned_ids = match metadata_writer.commit(self, batch).await {
                Ok(assigned_ids) => assigned_ids,
                Err(err) if err.is_assertion_failure() => {
                    for (create_id, _) in created_slots {
                        response.not_created.append(
                            create_id,
                            SetError::forbidden().with_description(
                                "Another process modified this contact card, please try again.",
                            ),
                        );
                    }
                    return Ok(response);
                }
                Err(err) => return Err(err.caused_by(trc::location!())),
            };

            for (create_id, slot) in created_slots {
                response.created(create_id, assigned_ids.slot(slot));
            }

            response.new_state =
                State::Exact(assigned_ids.last_change_id(account_id, SyncCollection::AddressBook));
        }

        // Destroy ids
        if on_success_delete && !destroy_ids.is_empty() {
            *next_call = Call {
                id: String::new(),
                name: MethodName::new(MethodObject::ContactCard, MethodFunction::Set),
                method: RequestMethod::Set(SetRequestMethod::ContactCard(Box::new(SetRequest {
                    account_id: request.from_account_id,
                    if_in_state: request.destroy_from_if_in_state,
                    create: None,
                    update: None,
                    destroy: MaybeResultReference::Value(destroy_ids).into(),
                    arguments: Default::default(),
                }))),
            }
            .into();
        }

        Ok(response)
    }
}
