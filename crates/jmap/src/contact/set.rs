/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::api::metadata::{
    MetadataAccess, MetadataPatches, MetadataTarget, MetadataType, MetadataWriter, NewMetadata,
    ObjectMetadata, PreparedMetadata, is_empty_update, reject_uncommitted,
};
use crate::api::pending_creates::PendingCreates;
use crate::blob::embedded::EmbeddedExport;
use crate::changes::state::JmapCacheState;
use crate::contact::assert_is_unique_uid;
use calcard::jscontact::{JSContact, JSContactProperty, JSContactValue};
use common::{
    DavName, GroupwareResources, Server,
    auth::{AccessToken, AccountCache},
    storage::quota::ObjectQuotaUsage,
};
use groupware::{
    DestroyArchive, SizeWriter,
    cache::GroupwareCache,
    contact::{ContactCard, ContactCardContent},
};
use http_proto::HttpSessionData;
use jmap_proto::{
    error::set::SetError,
    method::set::{SetRequest, SetResponse},
    object::contact,
    request::{MaybeInvalid, capability::CapabilityIds},
    types::state::State,
};
use jmap_tools::{JsonPointerHandler, JsonPointerItem, Key, Value};
use registry::schema::enums::StorageQuota;
use store::{
    ValueKey,
    ahash::AHashSet,
    roaring::RoaringBitmap,
    write::{Archive, ArchiveBytes, BatchBuilder, Slot},
};
use trc::AddContext;
use types::{
    acl::Acl,
    blob::BlobId,
    collection::{Collection, SyncCollection, VanishedCollection},
    field::ContactField,
    id::Id,
};

pub trait ContactCardSet: Sync + Send {
    fn contact_card_set(
        &self,
        request: SetRequest<'_, contact::ContactCard>,
        access_token: &AccessToken,
        session: &HttpSessionData,
        using: CapabilityIds,
    ) -> impl Future<Output = trc::Result<SetResponse<contact::ContactCard>>> + Send;

    #[allow(clippy::too_many_arguments)]
    fn create_contact_card(
        &self,
        cache: &GroupwareResources,
        batch: &mut BatchBuilder,
        access_token: &AccessToken,
        account: &AccountCache,
        account_id: u32,
        can_add_address_books: &Option<RoaringBitmap>,
        js_contact: JSContact<'_, Id, BlobId>,
        updates: Value<'_, JSContactProperty<Id>, JSContactValue<Id, BlobId>>,
        metadata_writer: &mut MetadataWriter,
        new_metadata: Option<NewMetadata>,
    ) -> impl Future<Output = trc::Result<Result<Slot, SetError<JSContactProperty<Id>>>>>;
}

impl ContactCardSet for Server {
    async fn contact_card_set(
        &self,
        mut request: SetRequest<'_, contact::ContactCard>,
        access_token: &AccessToken,
        _session: &HttpSessionData,
        using: CapabilityIds,
    ) -> trc::Result<SetResponse<contact::ContactCard>> {
        let account_id = request.account_id.document_id();
        let metadata = ObjectMetadata::new(self, access_token, using, MetadataType::ContactCard);
        let sampled = metadata.viewer_change_id(self, account_id).await?;
        let account = self.account(account_id).await.caused_by(trc::location!())?;
        let cache = self
            .fetch_groupware_resources(
                access_token.account_id(),
                account_id,
                SyncCollection::AddressBook,
            )
            .await?;
        let mut response = SetResponse::from_request(&request, self.core.jmap.set_max_objects)?
            .with_state(sampled.assert_state(cache.get_state(false), &request.if_in_state)?);
        let mut metadata_writer = MetadataWriter::new(metadata, account_id);
        let will_destroy = response.collect_will_destroy(request.unwrap_destroy());

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

        // Obtain quota
        let quota = if request.has_creates() {
            self.object_quota_usage(&account, StorageQuota::MaxContactCards, || {
                cache.resources.count(false)
            })
        } else {
            ObjectQuotaUsage::unlimited()
        };

        // Process creates
        let mut batch = BatchBuilder::new();
        let mut created_slots = PendingCreates::new();
        'create: for (id, mut object) in request.unwrap_create() {
            if !quota.has_room(created_slots.len()) {
                response.not_created.append(id, too_many_contacts());
                continue 'create;
            }
            let new_metadata =
                match metadata_writer.extract(MetadataPatches::for_create(), &mut object) {
                    Ok(patches) => patches.map(NewMetadata::Create),
                    Err(err) => {
                        response.not_created.append(id, err);
                        continue 'create;
                    }
                };

            match self
                .create_contact_card(
                    &cache,
                    &mut batch,
                    access_token,
                    &account,
                    account_id,
                    &can_add_address_books,
                    JSContact::default(),
                    object,
                    &mut metadata_writer,
                    new_metadata,
                )
                .await?
            {
                Ok(document_id) => {
                    created_slots.push(id, document_id);
                }
                Err(err) => {
                    response.not_created.append(id, err);
                    continue 'create;
                }
            }
        }

        // Process updates
        metadata_writer
            .preload_updates(self, request.update.as_ref(), |document_id| {
                cache
                    .item_by_id(document_id)
                    .map(|resource| resource.metadata_kinds())
            })
            .await?;
        'update: for (id, mut object) in request.unwrap_update() {
            let id = match id {
                MaybeInvalid::Value(id) => id,
                invalid => {
                    response.not_updated.append(invalid, SetError::not_found());
                    continue 'update;
                }
            };
            // Make sure id won't be destroyed
            if will_destroy.contains(&id) {
                response.not_updated.append(id, SetError::will_destroy());
                continue 'update;
            }
            let mut metadata_patches =
                match metadata_writer.extract(MetadataPatches::for_update(), &mut object) {
                    Ok(patches) => patches,
                    Err(err) => {
                        response.not_updated.append(id, err);
                        continue 'update;
                    }
                };

            // Obtain contact card
            let document_id = id.document_id();
            let contact_card_ = if let Some(contact_card_) = self
                .store()
                .get_value::<Archive<ArchiveBytes>>(ValueKey::archive(
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
            let metadata_access = if can_modify_address_books.is_some() {
                MetadataAccess {
                    may_write_shared: contact_card.inner.names.iter().any(|name| {
                        can_modify_address_books
                            .as_ref()
                            .is_some_and(|ids| ids.contains(name.parent_id.to_native()))
                    }),
                    may_read: contact_card.inner.names.iter().any(|name| {
                        cache
                            .container_acl(access_token, name.parent_id.to_native())
                            .contains(Acl::ReadItems)
                    }),
                }
            } else {
                MetadataAccess::FULL
            };
            if object
                .as_object()
                .is_some_and(|object| is_empty_update::<contact::ContactCard>(object, id))
                && let Some(patches) = metadata_patches.take()
            {
                match metadata_writer
                    .write_metadata_only::<ContactCard, _>(
                        self,
                        patches,
                        metadata_access,
                        &contact_card,
                        document_id,
                        &mut batch,
                    )
                    .await?
                {
                    Ok(()) => response.updated.append(id, None),
                    Err(err) => response.not_updated.append(id, err),
                }
                continue 'update;
            }
            let Some(content_) = self
                .store()
                .get_value::<Archive<ArchiveBytes>>(ValueKey::property(
                    account_id,
                    Collection::ContactCard,
                    document_id,
                    ContactField::Content,
                ))
                .await?
            else {
                response.not_updated.append(id, SetError::not_found());
                continue 'update;
            };
            let content = content_
                .to_unarchived::<ContactCardContent>()
                .caused_by(trc::location!())?;
            let mut new_contact_card = contact_card
                .deserialize::<ContactCard>()
                .caused_by(trc::location!())?;
            let mut new_content = content
                .deserialize::<ContactCardContent>()
                .caused_by(trc::location!())?;
            let mut js_contact = new_content.card.into_jscontact();

            // Process changes
            if let Err(err) = update_contact_card(
                Some(id),
                object,
                &mut new_contact_card.names,
                &mut js_contact,
            ) {
                response.not_updated.append(id, err);
                continue 'update;
            }

            // Convert JSContact to vCard
            match self.export_vcard(access_token, js_contact).await? {
                Ok(vcard) => {
                    new_content.card = vcard;
                }
                Err(err) => {
                    response.not_updated.append(id, err);
                    continue 'update;
                }
            }

            // Validate UID
            match (
                content.inner.card.uid().filter(|uid| !uid.is_empty()),
                new_content.card.uid().filter(|uid| !uid.is_empty()),
            ) {
                (Some(stored_uid), Some(uid)) if stored_uid == uid => {}
                (None, uid) => {
                    if let Err(err) = assert_is_unique_uid(&cache, &new_contact_card.names, uid)? {
                        response.not_updated.append(id, err);
                        continue 'update;
                    }
                }
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

            // Validate addressBookIds limit
            let max_address_books = self.core.groupware.max_address_books_per_card;
            if new_contact_card.names.len() > max_address_books
                && new_contact_card.names.len() > contact_card.inner.names.len()
            {
                response
                    .not_updated
                    .append(id, too_many_address_books(max_address_books));
                continue 'update;
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
            let size = SizeWriter::vcard(&new_content.card, self.core.groupware.vcard_version);
            if size > self.core.groupware.max_vcard_size {
                response.not_updated.append(
                    id,
                    contact_too_large(size, self.core.groupware.max_vcard_size),
                );
                continue 'update;
            }
            let extra_bytes =
                (size as u64).saturating_sub(u32::from(contact_card.inner.size) as u64);
            if extra_bytes > 0 {
                match self.has_available_quota(&account, extra_bytes).await {
                    Ok(_) => {}
                    Err(err) if err.matches(trc::EventType::Limit(trc::LimitEvent::Quota)) => {
                        response.not_updated.append(id, SetError::over_quota());
                        continue 'update;
                    }
                    Err(err) => return Err(err.caused_by(trc::location!())),
                }
            }

            let prepared_metadata = match metadata_patches {
                Some(patches) => match metadata_writer
                    .prepare_for(
                        self,
                        patches,
                        metadata_access,
                        MetadataTarget::Update { document_id },
                    )
                    .await?
                {
                    Ok(prepared) => Some(prepared),
                    Err(err) => {
                        response.not_updated.append(id, err);
                        continue 'update;
                    }
                },
                None => None,
            };

            // Update record
            let vanished_paths = new_contact_card
                .removed_addressbook_ids(contact_card.inner)
                .filter_map(|addressbook_id| {
                    cache.format_resource_path_by_parent(document_id, addressbook_id)
                })
                .collect::<Vec<_>>();
            if let Some(kinds) = prepared_metadata
                .as_ref()
                .and_then(PreparedMetadata::shared_kinds)
            {
                new_contact_card.set_metadata_kinds(kinds);
            }
            if let Some(prepared) = prepared_metadata {
                metadata_writer.write(prepared, document_id, &mut batch)?;
            }
            new_contact_card
                .update_full(
                    new_content,
                    self.core.groupware.vcard_version,
                    access_token.account_tenant_ids(),
                    contact_card,
                    content.inner,
                    account_id,
                    document_id,
                    None,
                    &mut batch,
                )
                .caused_by(trc::location!())?;
            for path in vanished_paths {
                batch.log_vanished_item(VanishedCollection::AddressBook, path);
            }
            response.updated.append(id, None);
        }

        // Process deletions
        let cleanup = self
            .preload_container_cleanup(
                Some(access_token.account_tenant_ids()),
                account_id,
                Collection::ContactCard,
                &will_destroy
                    .iter()
                    .map(|id| id.document_id())
                    .filter(|&document_id| {
                        cache
                            .item_by_id(document_id)
                            .is_some_and(|item| !item.metadata_kinds().is_empty())
                    })
                    .collect(),
            )
            .await
            .caused_by(trc::location!())?;
        'destroy: for id in will_destroy {
            let document_id = id.document_id();

            if !cache.has_item_id(&document_id) {
                response.not_destroyed.append(id, SetError::not_found());
                continue;
            };

            let Some(contact_card_) = self
                .store()
                .get_value::<Archive<ArchiveBytes>>(ValueKey::archive(
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
                .remove_all(
                    self,
                    access_token.account_tenant_ids(),
                    account_id,
                    document_id,
                    &cleanup,
                    &mut batch,
                )
                .await
                .caused_by(trc::location!())?;

            for path in cache.format_resource_paths_by_id(document_id) {
                batch.log_vanished_item(VanishedCollection::AddressBook, path);
            }

            response.destroyed.push(id);
        }

        // Write changes
        if !batch.is_empty() {
            let assigned_ids = match metadata_writer.commit(self, batch).await {
                Ok(assigned_ids) => assigned_ids,
                Err(err) if err.is_assertion_failure() => {
                    reject_uncommitted(
                        &mut response,
                        created_slots.into_create_ids(),
                        "Another process modified this contact card, please try again.",
                    );
                    return Ok(response);
                }
                Err(err) => return Err(err.caused_by(trc::location!())),
            };

            created_slots.resolve(&mut response, &assigned_ids);

            response.new_state =
                State::Exact(assigned_ids.last_change_id(account_id, SyncCollection::AddressBook))
                    .into();
        }

        Ok(response)
    }

    async fn create_contact_card(
        &self,
        cache: &GroupwareResources,
        batch: &mut BatchBuilder,
        access_token: &AccessToken,
        account: &AccountCache,
        account_id: u32,
        can_add_address_books: &Option<RoaringBitmap>,
        mut js_contact: JSContact<'_, Id, BlobId>,
        updates: Value<'_, JSContactProperty<Id>, JSContactValue<Id, BlobId>>,
        metadata_writer: &mut MetadataWriter,
        new_metadata: Option<NewMetadata>,
    ) -> trc::Result<Result<Slot, SetError<JSContactProperty<Id>>>> {
        // Process changes
        let mut names = Vec::new();
        if let Err(err) = update_contact_card(None, updates, &mut names, &mut js_contact) {
            return Ok(Err(err));
        }
        if names.len() > self.core.groupware.max_address_books_per_card {
            return Ok(Err(too_many_address_books(
                self.core.groupware.max_address_books_per_card,
            )));
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
        let card = match self.export_vcard(access_token, js_contact).await? {
            Ok(card) => card,
            Err(err) => return Ok(Err(err)),
        };

        // Validate UID
        if let Err(err) = assert_is_unique_uid(cache, &names, card.uid())? {
            return Ok(Err(err));
        }

        // Check size and quota
        let size = SizeWriter::vcard(&card, self.core.groupware.vcard_version);
        if size > self.core.groupware.max_vcard_size {
            return Ok(Err(contact_too_large(
                size,
                self.core.groupware.max_vcard_size,
            )));
        }
        match self.has_available_quota(account, size as u64).await {
            Ok(_) => {}
            Err(err) if err.matches(trc::EventType::Limit(trc::LimitEvent::Quota)) => {
                return Ok(Err(SetError::over_quota()));
            }
            Err(err) => return Err(err.caused_by(trc::location!())),
        }

        let metadata_access = match (&new_metadata, can_add_address_books) {
            (Some(_), Some(_)) => MetadataAccess {
                may_write_shared: names.iter().any(|name| {
                    cache
                        .container_acl(access_token, name.parent_id)
                        .contains(Acl::ModifyItems)
                }),
                may_read: names.iter().any(|name| {
                    cache
                        .container_acl(access_token, name.parent_id)
                        .contains(Acl::ReadItems)
                }),
            },
            _ => MetadataAccess::FULL,
        };
        let prepared_metadata = match metadata_writer
            .prepare_new(self, new_metadata, metadata_access)
            .await?
        {
            Ok(prepared) => prepared,
            Err(err) => return Ok(Err(err)),
        };

        // Insert record
        let document_id = batch.reserve_document_id(account_id, Collection::ContactCard);
        let mut contact_card = ContactCard {
            names,
            ..Default::default()
        };
        if let Some(kinds) = prepared_metadata
            .as_ref()
            .and_then(PreparedMetadata::shared_kinds)
        {
            contact_card.set_metadata_kinds(kinds);
        }
        if let Some(prepared) = prepared_metadata {
            metadata_writer.write(prepared, document_id, batch)?;
        }
        contact_card
            .insert(
                ContactCardContent { card },
                self.core.groupware.vcard_version,
                access_token.account_tenant_ids(),
                account_id,
                document_id,
                None,
                batch,
            )
            .caused_by(trc::location!())?;
        Ok(Ok(document_id))
    }
}

pub(crate) fn too_many_contacts() -> SetError<JSContactProperty<Id>> {
    SetError::over_quota().with_description(concat!(
        "There are too many contact cards, ",
        "please delete some before adding a new one."
    ))
}

fn contact_too_large(size: usize, max_size: usize) -> SetError<JSContactProperty<Id>> {
    SetError::too_large().with_description(format!(
        "Contact size {size} exceeds the maximum allowed size of {max_size} bytes."
    ))
}

fn too_many_address_books(max: usize) -> SetError<JSContactProperty<Id>> {
    SetError::invalid_properties()
        .with_property(JSContactProperty::AddressBookIds)
        .with_description(format!(
            "A contact card cannot belong to more than {max} address books."
        ))
}

fn update_contact_card<'x>(
    expected_id: Option<Id>,
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
                    let error = if expected_id.is_some() {
                        SetError::invalid_patch()
                    } else {
                        SetError::invalid_properties()
                    };
                    return Err(error
                        .with_property(JSContactProperty::Pointer(pointer))
                        .with_description("Patch operation failed."));
                }
                entries = js_contact.0.as_object_mut().unwrap();
            }
            (JSContactProperty::Id, value) => {
                if !expected_id.is_some_and(|expected| crate::matches_id(&value, expected)) {
                    return Err(SetError::invalid_properties()
                        .with_property(JSContactProperty::Id)
                        .with_description("The id property is immutable."));
                }
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
