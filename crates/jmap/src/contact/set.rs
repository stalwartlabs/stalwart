/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::contact::assert_is_unique_uid;
use calcard::jscontact::{JSContact, JSContactProperty, JSContactValue};
use common::{DavName, DavResources, Server, auth::AccessToken};
use groupware::{DestroyArchive, cache::GroupwareCache, contact::ContactCard};
use http_proto::HttpSessionData;
use jmap_proto::{
    error::set::SetError,
    method::set::{SetRequest, SetResponse},
    object::contact,
    request::IntoValid,
    types::state::State,
};
use jmap_tools::{JsonPointerHandler, JsonPointerItem, Key, Value};
use store::{
    ValueKey,
    ahash::AHashSet,
    roaring::RoaringBitmap,
    write::{AlignedBytes, Archive, BatchBuilder},
};
use trc::AddContext;
use types::{
    acl::Acl,
    blob::BlobId,
    collection::{Collection, SyncCollection},
    id::Id,
};

pub trait ContactCardSet: Sync + Send {
    fn contact_card_set(
        &self,
        request: SetRequest<'_, contact::ContactCard>,
        access_token: &AccessToken,
        session: &HttpSessionData,
    ) -> impl Future<Output = trc::Result<SetResponse<contact::ContactCard>>> + Send;

    #[allow(clippy::too_many_arguments)]
    fn create_contact_card(
        &self,
        cache: &DavResources,
        batch: &mut BatchBuilder,
        access_token: &AccessToken,
        account_id: u32,
        can_add_address_books: &Option<RoaringBitmap>,
        js_contact: JSContact<'_, Id, BlobId>,
        updates: Value<'_, JSContactProperty<Id>, JSContactValue<Id, BlobId>>,
    ) -> impl Future<Output = trc::Result<Result<u32, SetError<JSContactProperty<Id>>>>>;
}

impl ContactCardSet for Server {
    async fn contact_card_set(
        &self,
        mut request: SetRequest<'_, contact::ContactCard>,
        access_token: &AccessToken,
        _session: &HttpSessionData,
    ) -> trc::Result<SetResponse<contact::ContactCard>> {
        let account_id = request.account_id.document_id();
        let cache = self
            .fetch_dav_resources(access_token, account_id, SyncCollection::AddressBook)
            .await?;
        let mut response = SetResponse::from_request(&request, self.core.jmap.set_max_objects)?;
        let will_destroy = request.unwrap_destroy().into_valid().collect::<Vec<_>>();

        // Obtain addressBookIds
        let (can_add_address_books, can_delete_address_books, can_modify_address_books) =
            if access_token.is_shared(account_id) {
                (
                    cache
                        .shared_containers(access_token, [Acl::AddItems], true)
                        .into(),
                    cache
                        .shared_containers(access_token, [Acl::RemoveItems], true)
                        .into(),
                    cache
                        .shared_containers(access_token, [Acl::ModifyItems], true)
                        .into(),
                )
            } else {
                (None, None, None)
            };

        // Process creates
        let mut batch = BatchBuilder::new();
        'create: for (id, object) in request.unwrap_create() {
            match self
                .create_contact_card(
                    &cache,
                    &mut batch,
                    access_token,
                    account_id,
                    &can_add_address_books,
                    JSContact::default(),
                    object,
                )
                .await?
            {
                Ok(document_id) => {
                    response.created(id, document_id);
                }
                Err(err) => {
                    response.not_created.append(id, err);
                    continue 'create;
                }
            }
        }

        // Process updates
        'update: for (id, object) in request.unwrap_update().into_valid() {
            // Make sure id won't be destroyed
            if will_destroy.contains(&id) {
                response.not_updated.append(id, SetError::will_destroy());
                continue 'update;
            }

            // Obtain contact card
            let document_id = id.document_id();
            let contact_card_ = if let Some(contact_card_) = self
                .store()
                .get_value::<Archive<AlignedBytes>>(ValueKey::archive(
                    account_id,
                    Collection::ContactCard,
                    document_id,
                ))
                .await?
            {
                contact_card_
            } else {
                response.not_updated.append(id, SetError::not_found());
                continue 'update;
            };
            let contact_card = contact_card_
                .to_unarchived::<ContactCard>()
                .caused_by(trc::location!())?;
            let mut new_contact_card = contact_card
                .deserialize::<ContactCard>()
                .caused_by(trc::location!())?;
            let mut js_contact = new_contact_card.card.into_jscontact();

            // Process changes
            if let Err(err) =
                update_contact_card(object, &mut new_contact_card.names, &mut js_contact)
            {
                response.not_updated.append(id, err);
                continue 'update;
            }

            // Convert JSContact to vCard
            if let Some(vcard) = js_contact.into_vcard() {
                new_contact_card.size = vcard.size() as u32;
                new_contact_card.card = vcard;
            } else {
                response.not_updated.append(
                    id,
                    SetError::invalid_properties()
                        .with_description("Failed to convert contact to vCard."),
                );
                continue 'update;
            }

            // Validate UID
            match (new_contact_card.card.uid(), contact_card.inner.card.uid()) {
                (Some(old_uid), Some(new_uid)) if old_uid == new_uid => {}
                (None, None) | (None, Some(_)) => {}
                _ => {
                    response.not_updated.append(
                        id,
                        SetError::invalid_properties()
                            .with_property(JSContactProperty::Uid)
                            .with_description("You cannot change the UID of a contact."),
                    );
                    continue 'update;
                }
            }

            // Validate new addressBookIds
            for addressbook_id in new_contact_card.added_addressbook_ids(contact_card.inner) {
                if !cache.has_container_id(&addressbook_id) {
                    response.not_updated.append(
                        id,
                        SetError::invalid_properties()
                            .with_property(JSContactProperty::AddressBookIds)
                            .with_description(format!(
                                "addressBookId {} does not exist.",
                                Id::from(addressbook_id)
                            )),
                    );
                    continue 'update;
                } else if can_add_address_books
                    .as_ref()
                    .is_some_and(|ids| !ids.contains(addressbook_id))
                {
                    response.not_updated.append(
                        id,
                        SetError::forbidden().with_description(format!(
                            "You are not allowed to add contacts to address book {}.",
                            Id::from(addressbook_id)
                        )),
                    );
                    continue 'update;
                }
            }

            // Validate deleted addressBookIds
            if let Some(can_delete_address_books) = &can_delete_address_books {
                for addressbook_id in new_contact_card.removed_addressbook_ids(contact_card.inner) {
                    if !can_delete_address_books.contains(addressbook_id) {
                        response.not_updated.append(
                            id,
                            SetError::forbidden().with_description(format!(
                                "You are not allowed to remove contacts from address book {}.",
                                Id::from(addressbook_id)
                            )),
                        );
                        continue 'update;
                    }
                }
            }

            // Validate changed addressBookIds
            if let Some(can_modify_address_books) = &can_modify_address_books {
                for addressbook_id in new_contact_card.unchanged_addressbook_ids(contact_card.inner)
                {
                    if !can_modify_address_books.contains(addressbook_id) {
                        response.not_updated.append(
                            id,
                            SetError::forbidden().with_description(format!(
                                "You are not allowed to modify address book {}.",
                                Id::from(addressbook_id)
                            )),
                        );
                        continue 'update;
                    }
                }
            }

            // Check size and quota
            if new_contact_card.size as usize > self.core.groupware.max_vcard_size {
                response.not_updated.append(
                    id,
                    SetError::invalid_properties().with_description(format!(
                        "Contact size {} exceeds the maximum allowed size of {} bytes.",
                        new_contact_card.size, self.core.groupware.max_vcard_size
                    )),
                );
                continue 'update;
            }
            let extra_bytes = (new_contact_card.size as u64)
                .saturating_sub(u32::from(contact_card.inner.size) as u64);
            if extra_bytes > 0 {
                match self
                    .has_available_quota(
                        &self.get_resource_token(access_token, account_id).await?,
                        extra_bytes,
                    )
                    .await
                {
                    Ok(_) => {}
                    Err(err) if err.matches(trc::EventType::Limit(trc::LimitEvent::Quota)) => {
                        response.not_updated.append(id, SetError::over_quota());
                        continue 'update;
                    }
                    Err(err) => return Err(err.caused_by(trc::location!())),
                }
            }

            // Update record
            new_contact_card
                .update(
                    access_token,
                    contact_card,
                    account_id,
                    document_id,
                    &mut batch,
                )
                .caused_by(trc::location!())?;
            response.updated.append(id, None);
        }

        // Process deletions
        'destroy: for id in will_destroy {
            let document_id = id.document_id();

            if !cache.has_item_id(&document_id) {
                response.not_destroyed.append(id, SetError::not_found());
                continue;
            };

            let Some(contact_card_) = self
                .store()
                .get_value::<Archive<AlignedBytes>>(ValueKey::archive(
                    account_id,
                    Collection::ContactCard,
                    document_id,
                ))
                .await
                .caused_by(trc::location!())?
            else {
                response.not_destroyed.append(id, SetError::not_found());
                continue;
            };

            let contact_card = contact_card_
                .to_unarchived::<ContactCard>()
                .caused_by(trc::location!())?;

            // Validate ACLs
            if let Some(can_delete_address_books) = &can_delete_address_books {
                for name in contact_card.inner.names.iter() {
                    let parent_id = name.parent_id.to_native();
                    if !can_delete_address_books.contains(parent_id) {
                        response.not_destroyed.append(
                            id,
                            SetError::forbidden().with_description(format!(
                                "You are not allowed to remove contacts from address book {}.",
                                Id::from(parent_id)
                            )),
                        );
                        continue 'destroy;
                    }
                }
            }

            // Delete record
            DestroyArchive(contact_card)
                .delete_all(access_token, account_id, document_id, &mut batch)
                .caused_by(trc::location!())?;

            response.destroyed.push(id);
        }

        // Write changes
        if !batch.is_empty() {
            let change_id = self
                .commit_batch(batch)
                .await
                .and_then(|ids| ids.last_change_id(account_id))
                .caused_by(trc::location!())?;

            self.notify_task_queue();

            response.new_state = State::Exact(change_id).into();
        }

        Ok(response)
    }

    async fn create_contact_card(
        &self,
        cache: &DavResources,
        batch: &mut BatchBuilder,
        access_token: &AccessToken,
        account_id: u32,
        can_add_address_books: &Option<RoaringBitmap>,
        mut js_contact: JSContact<'_, Id, BlobId>,
        updates: Value<'_, JSContactProperty<Id>, JSContactValue<Id, BlobId>>,
    ) -> trc::Result<Result<u32, SetError<JSContactProperty<Id>>>> {
        // Process changes
        let mut names = Vec::new();
        if let Err(err) = update_contact_card(updates, &mut names, &mut js_contact) {
            return Ok(Err(err));
        }

        // Verify that the address book ids valid
        for name in &names {
            if !cache.has_container_id(&name.parent_id) {
                return Ok(Err(SetError::invalid_properties()
                    .with_property(JSContactProperty::AddressBookIds)
                    .with_description(format!(
                        "addressBookId {} does not exist.",
                        Id::from(name.parent_id)
                    ))));
            } else if can_add_address_books
                .as_ref()
                .is_some_and(|ids| !ids.contains(name.parent_id))
            {
                return Ok(Err(SetError::forbidden().with_description(format!(
                    "You are not allowed to add contacts to address book {}.",
                    Id::from(name.parent_id)
                ))));
            }
        }

        // Convert JSContact to vCard
        let Some(card) = js_contact.into_vcard() else {
            return Ok(Err(SetError::invalid_properties()
                .with_description("Failed to convert contact to vCard.")));
        };

        // Validate UID
        if let Err(err) = assert_is_unique_uid(self, cache, account_id, &names, card.uid()).await? {
            return Ok(Err(err));
        }

        // Check size and quota
        let size = card.size();
        if size > self.core.groupware.max_vcard_size {
            return Ok(Err(SetError::invalid_properties().with_description(
                format!(
                    "Contact size {} exceeds the maximum allowed size of {} bytes.",
                    size, self.core.groupware.max_vcard_size
                ),
            )));
        }
        match self
            .has_available_quota(
                &self.get_resource_token(access_token, account_id).await?,
                size as u64,
            )
            .await
        {
            Ok(_) => {}
            Err(err) if err.matches(trc::EventType::Limit(trc::LimitEvent::Quota)) => {
                return Ok(Err(SetError::over_quota()));
            }
            Err(err) => return Err(err.caused_by(trc::location!())),
        }

        // Insert record
        let document_id = self
            .store()
            .assign_document_ids(account_id, Collection::ContactCard, 1)
            .await
            .caused_by(trc::location!())?;
        ContactCard {
            names,
            size: size as u32,
            card,
            ..Default::default()
        }
        .insert(access_token, account_id, document_id, batch)
        .caused_by(trc::location!())
        .map(|_| Ok(document_id))
    }
}

fn update_contact_card<'x>(
    updates: Value<'x, JSContactProperty<Id>, JSContactValue<Id, BlobId>>,
    addressbooks: &mut Vec<DavName>,
    js_contact: &mut JSContact<'x, Id, BlobId>,
) -> Result<(), SetError<JSContactProperty<Id>>> {
    let mut entries = js_contact.0.as_object_mut().unwrap();

    for (property, value) in updates.into_expanded_object() {
        let Key::Property(property) = property else {
            return Err(SetError::invalid_properties()
                .with_property(property.to_owned())
                .with_description("Invalid property."));
        };

        match (property, value) {
            (JSContactProperty::AddressBookIds, value) => {
                patch_parent_ids(addressbooks, None, value)?;
            }
            (JSContactProperty::Pointer(pointer), value) => {
                if matches!(
                    pointer.first(),
                    Some(JsonPointerItem::Key(Key::Property(
                        JSContactProperty::AddressBookIds
                    )))
                ) {
                    let mut pointer = pointer.iter();
                    pointer.next();
                    patch_parent_ids(addressbooks, pointer.next(), value)?;
                } else if !js_contact.0.patch_jptr(pointer.iter(), value) {
                    return Err(SetError::invalid_properties()
                        .with_property(JSContactProperty::Pointer(pointer))
                        .with_description("Patch operation failed."));
                }
                entries = js_contact.0.as_object_mut().unwrap();
            }
            (JSContactProperty::Media, Value::Object(media)) => {
                for (_, value) in media.iter() {
                    if value.as_object().is_some_and(|v| {
                        v.keys()
                            .any(|k| matches!(k, Key::Property(JSContactProperty::BlobId)))
                    }) {
                        return Err(SetError::invalid_properties()
                            .with_property(JSContactProperty::Media)
                            .with_description("blobIds in media is not supported."));
                    }
                }
                entries.insert(JSContactProperty::Media, Value::Object(media));
            }
            (property, value) => {
                entries.insert(property, value);
            }
        }
    }

    // Make sure the contact belongs to at least one address book
    if addressbooks.is_empty() {
        return Err(SetError::invalid_properties()
            .with_property(JSContactProperty::AddressBookIds)
            .with_description("Contact has to belong to at least one address book."));
    }

    Ok(())
}

fn patch_parent_ids(
    current: &mut Vec<DavName>,
    patch: Option<&JsonPointerItem<JSContactProperty<Id>>>,
    update: Value<'_, JSContactProperty<Id>, JSContactValue<Id, BlobId>>,
) -> Result<(), SetError<JSContactProperty<Id>>> {
    match (patch, update) {
        (
            Some(JsonPointerItem::Key(Key::Property(JSContactProperty::IdValue(id)))),
            Value::Bool(false) | Value::Null,
        ) => {
            let id = id.document_id();
            current.retain(|name| name.parent_id != id);
            Ok(())
        }
        (
            Some(JsonPointerItem::Key(Key::Property(JSContactProperty::IdValue(id)))),
            Value::Bool(true),
        ) => {
            let id = id.document_id();
            if !current.iter().any(|name| name.parent_id == id) {
                current.push(DavName::new_with_rand_name(id));
            }
            Ok(())
        }
        (None, Value::Object(object)) => {
            let mut new_ids = object
                .into_expanded_boolean_set()
                .filter_map(|id| {
                    if let Key::Property(JSContactProperty::IdValue(id)) = id {
                        Some(id.document_id())
                    } else {
                        None
                    }
                })
                .collect::<AHashSet<_>>();

            current.retain(|name| new_ids.remove(&name.parent_id));

            for id in new_ids {
                current.push(DavName::new_with_rand_name(id));
            }

            Ok(())
        }
        _ => Err(SetError::invalid_properties()
            .with_property(JSContactProperty::AddressBookIds)
            .with_description("Invalid patch operation for addressBookIds.")),
    }
}
