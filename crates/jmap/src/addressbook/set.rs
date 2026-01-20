/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::api::acl::{JmapAcl, JmapRights};
use common::{Server, auth::AccessToken, sharing::EffectiveAcl};
use groupware::{
    DestroyArchive,
    cache::GroupwareCache,
    contact::{AddressBook, AddressBookPreferences, ContactCard},
};
use http_proto::HttpSessionData;
use jmap_proto::{
    error::set::SetError,
    method::set::{SetRequest, SetResponse},
    object::addressbook::{self, AddressBookProperty, AddressBookValue},
    request::{IntoValid, reference::MaybeIdReference},
    types::state::State,
};
use jmap_tools::{JsonPointerItem, Key, Value};
use rand::{Rng, distr::Alphanumeric};
use store::{
    SerializeInfallible, ValueKey,
    ahash::AHashSet,
    write::{AlignedBytes, Archive, BatchBuilder, ValueClass},
};
use trc::AddContext;
use types::{
    acl::Acl,
    collection::{Collection, SyncCollection},
    field::PrincipalField,
};

pub trait AddressBookSet: Sync + Send {
    fn address_book_set(
        &self,
        request: SetRequest<'_, addressbook::AddressBook>,
        access_token: &AccessToken,
        session: &HttpSessionData,
    ) -> impl Future<Output = trc::Result<SetResponse<addressbook::AddressBook>>> + Send;
}

impl AddressBookSet for Server {
    async fn address_book_set(
        &self,
        mut request: SetRequest<'_, addressbook::AddressBook>,
        access_token: &AccessToken,
        _session: &HttpSessionData,
    ) -> trc::Result<SetResponse<addressbook::AddressBook>> {
        let account_id = request.account_id.document_id();
        let cache = self
            .fetch_dav_resources(access_token, account_id, SyncCollection::AddressBook)
            .await?;
        let mut response = SetResponse::from_request(&request, self.core.jmap.set_max_objects)?;
        let will_destroy = request.unwrap_destroy().into_valid().collect::<Vec<_>>();
        let is_shared = access_token.is_shared(account_id);
        let mut set_default = None;

        // Process creates
        let mut batch = BatchBuilder::new();
        'create: for (id, object) in request.unwrap_create() {
            if is_shared {
                response.not_created.append(
                    id,
                    SetError::forbidden()
                        .with_description("Cannot create address books in a shared account."),
                );
                continue 'create;
            }

            let mut address_book = AddressBook {
                name: rand::rng()
                    .sample_iter(Alphanumeric)
                    .take(10)
                    .map(char::from)
                    .collect::<String>(),
                preferences: vec![AddressBookPreferences {
                    account_id,
                    name: "Address Book".to_string(),
                    ..Default::default()
                }],
                ..Default::default()
            };

            // Process changes
            if let Err(err) = update_address_book(object, &mut address_book, account_id) {
                response.not_created.append(id, err);
                continue 'create;
            }

            // Validate ACLs
            if !address_book.acls.is_empty() {
                if let Err(err) = self.acl_validate(&address_book.acls).await {
                    response.not_created.append(id, err.into());
                    continue 'create;
                }

                self.refresh_acls(&address_book.acls, None).await;
            }

            // Insert record
            let document_id = self
                .store()
                .assign_document_ids(account_id, Collection::AddressBook, 1)
                .await
                .caused_by(trc::location!())?;
            address_book
                .insert(access_token, account_id, document_id, &mut batch)
                .caused_by(trc::location!())?;

            if let Some(MaybeIdReference::Reference(id_ref)) =
                &request.arguments.on_success_set_is_default
                && id_ref == &id
            {
                set_default = Some(document_id);
            }

            response.created(id, document_id);
        }

        // Process updates
        'update: for (id, object) in request.unwrap_update().into_valid() {
            // Make sure id won't be destroyed
            if will_destroy.contains(&id) {
                response.not_updated.append(id, SetError::will_destroy());
                continue 'update;
            }

            // Obtain address book
            let document_id = id.document_id();
            let address_book_ = if let Some(address_book_) = self
                .store()
                .get_value::<Archive<AlignedBytes>>(ValueKey::archive(
                    account_id,
                    Collection::AddressBook,
                    document_id,
                ))
                .await?
            {
                address_book_
            } else {
                response.not_updated.append(id, SetError::not_found());
                continue 'update;
            };
            let address_book = address_book_
                .to_unarchived::<AddressBook>()
                .caused_by(trc::location!())?;
            let mut new_address_book = address_book
                .deserialize::<AddressBook>()
                .caused_by(trc::location!())?;

            // Apply changes
            let has_acl_changes =
                match update_address_book(object, &mut new_address_book, account_id) {
                    Ok(has_acl_changes_) => has_acl_changes_,
                    Err(err) => {
                        response.not_updated.append(id, err);
                        continue 'update;
                    }
                };

            // Validate ACL
            if is_shared {
                let acl = address_book.inner.acls.effective_acl(access_token);
                if !acl.contains(Acl::Modify) || (has_acl_changes && !acl.contains(Acl::Share)) {
                    response.not_updated.append(
                        id,
                        SetError::forbidden()
                            .with_description("You are not allowed to modify this address book."),
                    );
                    continue 'update;
                }
            }
            if has_acl_changes {
                if let Err(err) = self.acl_validate(&new_address_book.acls).await {
                    response.not_updated.append(id, err.into());
                    continue 'update;
                }
                self.refresh_archived_acls(
                    &new_address_book.acls,
                    address_book.inner.acls.as_slice(),
                )
                .await;
            }

            // Update record
            new_address_book
                .update(
                    access_token,
                    address_book,
                    account_id,
                    document_id,
                    &mut batch,
                )
                .caused_by(trc::location!())?;
            response.updated.append(id, None);
        }

        // Process deletions
        let mut reset_default_address_book = false;
        if !will_destroy.is_empty() {
            let mut destroy_children = AHashSet::new();
            let mut destroy_parents = AHashSet::new();
            let default_address_book_id = self
                .store()
                .get_value::<u32>(ValueKey {
                    account_id,
                    collection: Collection::Principal.into(),
                    document_id: 0,
                    class: ValueClass::Property(PrincipalField::DefaultAddressBookId.into()),
                })
                .await
                .caused_by(trc::location!())?;

            let on_destroy_remove_contents = request
                .arguments
                .on_destroy_remove_contents
                .unwrap_or(false);

            for id in will_destroy {
                let document_id = id.document_id();

                if !cache.has_container_id(&document_id) {
                    response.not_destroyed.append(id, SetError::not_found());
                    continue;
                };

                let Some(address_book_) = self
                    .store()
                    .get_value::<Archive<AlignedBytes>>(ValueKey::archive(
                        account_id,
                        Collection::AddressBook,
                        document_id,
                    ))
                    .await
                    .caused_by(trc::location!())?
                else {
                    response.not_destroyed.append(id, SetError::not_found());
                    continue;
                };

                let address_book = address_book_
                    .to_unarchived::<AddressBook>()
                    .caused_by(trc::location!())?;

                // Validate ACLs
                if is_shared
                    && !address_book
                        .inner
                        .acls
                        .effective_acl(access_token)
                        .contains_all([Acl::Delete, Acl::RemoveItems].into_iter())
                {
                    response.not_destroyed.append(
                        id,
                        SetError::forbidden()
                            .with_description("You are not allowed to delete this address book."),
                    );
                    continue;
                }

                // Obtain children ids
                let children_ids = cache.children_ids(document_id).collect::<Vec<_>>();
                if !children_ids.is_empty() && !on_destroy_remove_contents {
                    response
                        .not_destroyed
                        .append(id, SetError::address_book_has_contents());
                    continue;
                }
                destroy_children.extend(children_ids.iter().copied());
                destroy_parents.insert(document_id);

                // Delete record
                DestroyArchive(address_book)
                    .delete(access_token, account_id, document_id, None, &mut batch)
                    .caused_by(trc::location!())?;

                if default_address_book_id == Some(document_id) {
                    reset_default_address_book = true;
                }

                response.destroyed.push(id);
            }

            // Delete children
            if !destroy_children.is_empty() {
                for document_id in destroy_children {
                    if let Some(card_) = self
                        .store()
                        .get_value::<Archive<AlignedBytes>>(ValueKey::archive(
                            account_id,
                            Collection::ContactCard,
                            document_id,
                        ))
                        .await?
                    {
                        let card = card_
                            .to_unarchived::<ContactCard>()
                            .caused_by(trc::location!())?;

                        if card
                            .inner
                            .names
                            .iter()
                            .all(|n| destroy_parents.contains(&n.parent_id.to_native()))
                        {
                            // Card only belongs to address books being deleted, delete it
                            DestroyArchive(card).delete_all(
                                access_token,
                                account_id,
                                document_id,
                                &mut batch,
                            )?;
                        } else {
                            // Unlink addressbook id from card
                            let mut new_card = card
                                .deserialize::<ContactCard>()
                                .caused_by(trc::location!())?;
                            new_card
                                .names
                                .retain(|n| !destroy_parents.contains(&n.parent_id));
                            new_card.update(
                                access_token,
                                card,
                                account_id,
                                document_id,
                                &mut batch,
                            )?;
                        }
                    }
                }
            }
        }

        // Set default address book
        if let Some(MaybeIdReference::Id(id)) = &request.arguments.on_success_set_is_default {
            set_default = Some(id.document_id());
        }
        if let Some(default_address_book_id) = set_default {
            if response.not_created.is_empty()
                && response.not_updated.is_empty()
                && response.not_destroyed.is_empty()
            {
                batch
                    .with_account_id(account_id)
                    .with_collection(Collection::Principal)
                    .with_document(0)
                    .set(
                        PrincipalField::DefaultAddressBookId,
                        default_address_book_id.serialize(),
                    );
            }
        } else if reset_default_address_book {
            batch
                .with_account_id(account_id)
                .with_collection(Collection::Principal)
                .with_document(0)
                .clear(PrincipalField::DefaultAddressBookId);
        }

        // Write changes
        if !batch.is_empty()
            && let Ok(change_id) = self
                .commit_batch(batch)
                .await
                .caused_by(trc::location!())?
                .last_change_id(account_id)
        {
            self.notify_task_queue();
            response.new_state = State::Exact(change_id).into();
        }

        Ok(response)
    }
}

fn update_address_book(
    updates: Value<'_, AddressBookProperty, AddressBookValue>,
    address_book: &mut AddressBook,
    account_id: u32,
) -> Result<bool, SetError<AddressBookProperty>> {
    let mut has_acl_changes = false;

    for (property, value) in updates.into_expanded_object() {
        let Key::Property(property) = property else {
            return Err(SetError::invalid_properties()
                .with_property(property.to_owned())
                .with_description("Invalid property."));
        };

        match (property, value) {
            (AddressBookProperty::Name, Value::Str(value)) if (1..=255).contains(&value.len()) => {
                address_book.preferences_mut(account_id).name = value.into_owned();
            }
            (AddressBookProperty::Description, Value::Str(value)) if value.len() < 255 => {
                address_book.preferences_mut(account_id).description = value.into_owned().into();
            }
            (AddressBookProperty::Description, Value::Null) => {
                address_book.preferences_mut(account_id).description = None;
            }
            (AddressBookProperty::SortOrder, Value::Number(value)) => {
                address_book.preferences_mut(account_id).sort_order = value.cast_to_u64() as u32;
            }
            (AddressBookProperty::IsSubscribed, Value::Bool(subscribe)) => {
                if subscribe {
                    if !address_book.subscribers.contains(&account_id) {
                        address_book.subscribers.push(account_id);
                    }
                } else {
                    address_book.subscribers.retain(|id| *id != account_id);
                }
            }
            (AddressBookProperty::ShareWith, value) => {
                address_book.acls = JmapRights::acl_set::<addressbook::AddressBook>(value)?;
                has_acl_changes = true;
            }
            (AddressBookProperty::Pointer(pointer), value)
                if matches!(
                    pointer.first(),
                    Some(JsonPointerItem::Key(Key::Property(
                        AddressBookProperty::ShareWith
                    )))
                ) =>
            {
                let mut pointer = pointer.iter();
                pointer.next();

                address_book.acls = JmapRights::acl_patch::<addressbook::AddressBook>(
                    std::mem::take(&mut address_book.acls),
                    pointer,
                    value,
                )?;
                has_acl_changes = true;
            }
            (property, _) => {
                return Err(SetError::invalid_properties()
                    .with_property(property.clone())
                    .with_description("Field could not be set."));
            }
        }
    }

    // Validate name
    if address_book.preferences(account_id).name.is_empty() {
        return Err(SetError::invalid_properties()
            .with_property(AddressBookProperty::Name)
            .with_description("Missing name."));
    }

    Ok(has_acl_changes)
}
