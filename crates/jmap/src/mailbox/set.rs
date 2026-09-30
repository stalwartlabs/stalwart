/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    api::{
        acl::{JmapAcl, JmapRights},
        metadata::{
            ContainerTarget, MetadataAccess, MetadataPatches, MetadataType, ObjectMetadata,
            is_empty_update,
        },
        parent_ref::{CreateResolver, ParentRef},
    },
    changes::state::{JmapCacheState, MetadataStateManager},
};
use common::{
    Server,
    auth::AccessToken,
    sharing::EffectiveAcl,
    storage::{
        index::ObjectIndexBuilder,
        metadata::{MetadataLog, PrivateMetadataCommit},
    },
};
use email::{
    cache::{MessageCacheFetch, mailbox::MailboxCacheAccess},
    cleanup::FlaggedContainers,
    mailbox::{
        Mailbox,
        destroy::{MailboxDestroy, MailboxDestroyError},
        merge_subscription,
        role::RoleChange,
    },
    presence::update_mailbox_presence,
};
use jmap_proto::{
    error::set::{SetError, SetErrorType},
    method::set::{SetRequest, SetResponse},
    object::{
        AnyId,
        mailbox::{self, MailboxProperty, MailboxValue},
    },
    references::resolve::ResolveCreatedReference,
    request::{MaybeInvalid, capability::CapabilityIds},
    types::state::State,
};
use jmap_tools::{JsonPointerItem, Key, Map, Value};
use registry::schema::enums::StorageQuota;
use std::future::Future;
use store::{
    ValueKey,
    ahash::AHashMap,
    roaring::RoaringBitmap,
    write::{Archive, ArchiveBytes, BatchBuilder, Slot, assert::AssertValue},
};
use trc::AddContext;
use types::{
    acl::Acl,
    collection::{Collection, SyncCollection},
    field::MailboxField,
    id::Id,
    special_use::SpecialUse,
};

pub struct SetContext<'x> {
    account_id: u32,
    access_token: &'x AccessToken,
    is_shared: bool,
    response: SetResponse<mailbox::Mailbox>,
    mailbox_ids: RoaringBitmap,
    will_destroy: Vec<Id>,
}

pub trait MailboxSet: Sync + Send {
    fn mailbox_set(
        &self,
        request: SetRequest<'_, mailbox::Mailbox>,
        access_token: &AccessToken,
        using: CapabilityIds,
    ) -> impl Future<Output = trc::Result<SetResponse<mailbox::Mailbox>>> + Send;

    #[allow(clippy::type_complexity)]
    fn mailbox_set_item(
        &self,
        changes_: Map<'_, MailboxProperty, MailboxValue>,
        update: Option<(u32, Archive<Mailbox>)>,
        ctx: &SetContext,
        resolver: Option<&CreateResolver<'_>>,
    ) -> impl Future<
        Output = trc::Result<
            Result<
                (ObjectIndexBuilder<Archive<Mailbox>, Mailbox>, ParentRef),
                SetError<MailboxProperty>,
            >,
        >,
    > + Send;
}

impl ResolveCreatedReference<MailboxProperty, MailboxValue> for CreateResolver<'_> {
    fn get_created_id(&self, id_ref: &str) -> Option<AnyId> {
        self.created_id(id_ref)
    }
}

impl MailboxSet for Server {
    #[allow(clippy::blocks_in_conditions)]
    async fn mailbox_set(
        &self,
        mut request: SetRequest<'_, mailbox::Mailbox>,
        access_token: &AccessToken,
        using: CapabilityIds,
    ) -> trc::Result<SetResponse<mailbox::Mailbox>> {
        // Prepare response
        let account_id = request.account_id.document_id();
        let on_destroy_remove_emails = request.arguments.on_destroy_remove_emails.unwrap_or(false);
        let cache = self.get_cached_messages(account_id).await?;
        let object_metadata = ObjectMetadata::new(self, access_token, using, MetadataType::Mailbox);
        let viewer = object_metadata.viewer();
        let shared_state = cache.get_state(true);
        let mut response = SetResponse::from_request(&request, self.core.jmap.set_max_objects)?
            .with_state(
                self.assert_metadata_state(
                    viewer,
                    account_id,
                    Collection::Mailbox,
                    shared_state.clone(),
                    &request.if_in_state,
                )
                .await?,
            );
        let metadata_support = object_metadata.support();
        let containers = object_metadata
            .preload_updates(self, account_id, request.update.as_ref(), |document_id| {
                cache
                    .mailbox_by_id(&document_id)
                    .map(|mailbox| mailbox.metadata_kinds)
            })
            .await?;
        let mut commit = PrivateMetadataCommit::default();
        let mut private_batch = BatchBuilder::new();
        let mut private_commit = PrivateMetadataCommit::default();
        let mut will_update_private = Vec::new();
        let mut has_private_changes = false;
        let will_destroy = response.collect_will_destroy(request.unwrap_destroy());
        let mut ctx = SetContext {
            account_id,
            is_shared: access_token.is_shared(account_id),
            access_token,
            response,
            mailbox_ids: RoaringBitmap::from_iter(cache.mailboxes.index.keys()),
            will_destroy,
        };
        let mut change_id = None;
        let account_info = self.account(account_id).await?;

        // Process creates
        let mut batch = BatchBuilder::new();
        let mut pending_creates: AHashMap<String, Slot> = AHashMap::new();
        'create: for (id, mut object) in request.unwrap_create() {
            let metadata_patches =
                match object_metadata.extract(MetadataPatches::for_create(), &mut object) {
                    Ok(patches) => patches,
                    Err(err) => {
                        ctx.response.not_created.append(id, err);
                        continue 'create;
                    }
                };
            let Some(object) = object.into_object() else {
                continue;
            };

            // Validate quota
            if ctx.mailbox_ids.len() + pending_creates.len() as u64
                >= self.object_quota(account_info.object_quotas(), StorageQuota::MaxMailboxes)
                    as u64
            {
                ctx.response.not_created.append(
                    id,
                    SetError::new(SetErrorType::OverQuota).with_description(concat!(
                        "There are too many mailboxes, ",
                        "please delete some before adding a new one."
                    )),
                );
                continue 'create;
            }

            match self
                .mailbox_set_item(
                    object,
                    None,
                    &ctx,
                    Some(&CreateResolver::new(&pending_creates)),
                )
                .await?
            {
                Ok((mut builder, parent)) => {
                    let metadata_writes = if let Some(metadata_patches) = metadata_patches {
                        let Some(support) = metadata_support else {
                            ctx.response
                                .not_created
                                .append(id, metadata_patches.unsupported());
                            continue 'create;
                        };
                        let access = MetadataAccess {
                            may_write_shared: true,
                            may_read: true,
                        };
                        let update = match metadata_patches.apply(support, access, None, None) {
                            Ok(update) => update,
                            Err(err) => {
                                ctx.response.not_created.append(id, err);
                                continue 'create;
                            }
                        };
                        match update
                            .prepare(
                                self,
                                ContainerTarget {
                                    owner: &account_info,
                                    viewer_id: access_token.account_id(),
                                    collection: Collection::Mailbox,
                                    log: MetadataLog::None,
                                },
                            )
                            .await?
                        {
                            Ok(prepared) => {
                                if let Some((kinds, mailbox)) =
                                    prepared.shared_kinds().zip(builder.changes_mut())
                                {
                                    mailbox.set_metadata_kinds(kinds);
                                }
                                Some(prepared)
                            }
                            Err(err) => {
                                ctx.response.not_created.append(id, err);
                                continue 'create;
                            }
                        }
                    } else {
                        None
                    };

                    batch
                        .with_account_id(account_id)
                        .with_collection(Collection::Mailbox);

                    if let Some(parent_document_id) = parent.document_id() {
                        batch
                            .with_document(parent_document_id)
                            .assert_value(MailboxField::Archive, AssertValue::Some);
                    }

                    let slot = batch.reserve_document_id(account_id, Collection::Mailbox);
                    batch
                        .create_document(slot)
                        .custom(builder.with_pending_id_opt(parent.slot()))
                        .caused_by(trc::location!())?;
                    if let Some(prepared) = metadata_writes {
                        prepared
                            .build(slot, &mut batch, &mut commit)
                            .caused_by(trc::location!())?;
                    }
                    batch.commit_point();

                    pending_creates.insert(id, slot);
                }
                Err(err) => {
                    ctx.response.not_created.append(id, err);
                    continue 'create;
                }
            }
        }

        if !batch.is_empty() {
            let assigned_ids = self.commit_batch(batch).await.caused_by(trc::location!())?;
            change_id = assigned_ids
                .last_change_id(account_id, SyncCollection::Email)
                .into();
            self.private_metadata_committed(std::mem::take(&mut commit), &assigned_ids)
                .await;

            for (id, slot) in pending_creates {
                let document_id = assigned_ids.slot(slot);
                ctx.mailbox_ids.insert(document_id);
                ctx.response.created(id, document_id);
            }
        }

        // Process updates
        let mut will_update = Vec::with_capacity(request.update.as_ref().map_or(0, |u| u.len()));
        let mut batch = BatchBuilder::new();
        'update: for (id, mut object) in request.unwrap_update() {
            let id = match id {
                MaybeInvalid::Value(id) => id,
                invalid => {
                    ctx.response
                        .not_updated
                        .append(invalid, SetError::not_found());
                    continue 'update;
                }
            };
            // Make sure id won't be destroyed
            if ctx.will_destroy.contains(&id) {
                ctx.response
                    .not_updated
                    .append(id, SetError::will_destroy());
                continue 'update;
            }
            let metadata_patches =
                match object_metadata.extract(MetadataPatches::for_update(), &mut object) {
                    Ok(patches) => patches,
                    Err(err) => {
                        ctx.response.not_updated.append(id, err);
                        continue 'update;
                    }
                };
            let Some(object) = object.into_object() else {
                continue 'update;
            };

            // Obtain mailbox
            let document_id = id.document_id();
            if let Some(mailbox_archive) = self
                .store()
                .get_value::<Archive<ArchiveBytes>>(ValueKey::archive(
                    account_id,
                    Collection::Mailbox,
                    document_id,
                ))
                .await?
            {
                // Validate ACL
                let mailbox = mailbox_archive
                    .into_deserialized::<email::mailbox::Mailbox>()
                    .caused_by(trc::location!())?;
                let subscription_only = object.keys().all(|key| {
                    matches!(
                        key,
                        Key::Property(MailboxProperty::IsSubscribed | MailboxProperty::Id)
                    )
                });
                let acl = ctx
                    .is_shared
                    .then(|| mailbox.inner.acls.effective_acl(access_token));
                if let Some(acl) = acl {
                    if subscription_only {
                        if !acl.contains(Acl::Read) {
                            ctx.response.not_updated.append(
                                id,
                                SetError::forbidden().with_description(
                                    "You are not allowed to access this mailbox.",
                                ),
                            );
                            continue 'update;
                        }
                    } else if !acl.contains(Acl::Modify) {
                        ctx.response.not_updated.append(
                            id,
                            SetError::forbidden()
                                .with_description("You are not allowed to modify this mailbox."),
                        );
                        continue 'update;
                    } else if object.contains_key(&Key::Property(MailboxProperty::ShareWith))
                        && !acl.contains(Acl::Share)
                    {
                        ctx.response.not_updated.append(
                            id,
                            SetError::forbidden().with_description(
                                "You are not allowed to change the permissions of this mailbox.",
                            ),
                        );
                        continue 'update;
                    }
                }

                let metadata_writes = if let Some(metadata_patches) = metadata_patches {
                    let Some(support) = metadata_support else {
                        ctx.response
                            .not_updated
                            .append(id, metadata_patches.unsupported());
                        continue 'update;
                    };
                    let access = MetadataAccess {
                        may_write_shared: acl.is_none_or(|acl| acl.contains(Acl::Modify)),
                        may_read: acl.is_none_or(|acl| acl.contains(Acl::Read)),
                    };
                    let update = match metadata_patches.apply(
                        support,
                        access,
                        containers.shared.get(document_id),
                        containers.private.get(document_id),
                    ) {
                        Ok(update) => update,
                        Err(err) => {
                            ctx.response.not_updated.append(id, err);
                            continue 'update;
                        }
                    };
                    if update.is_empty() {
                        None
                    } else {
                        match update
                            .prepare(
                                self,
                                ContainerTarget {
                                    owner: &account_info,
                                    viewer_id: access_token.account_id(),
                                    collection: Collection::Mailbox,
                                    log: MetadataLog::Container,
                                },
                            )
                            .await?
                        {
                            Ok(prepared) => Some(prepared),
                            Err(err) => {
                                ctx.response.not_updated.append(id, err);
                                continue 'update;
                            }
                        }
                    }
                } else {
                    None
                };

                if is_empty_update::<mailbox::Mailbox>(&object, id) {
                    match metadata_writes {
                        Some(prepared) => {
                            let is_private_only = prepared.is_private_only();
                            let (target, target_commit) = if is_private_only {
                                (&mut private_batch, &mut private_commit)
                            } else {
                                (&mut batch, &mut commit)
                            };
                            if let Some(presence) = prepared
                                .build(document_id, target, target_commit)
                                .caused_by(trc::location!())?
                            {
                                update_mailbox_presence(
                                    target,
                                    account_id,
                                    document_id,
                                    &mailbox_archive
                                        .to_unarchived::<email::mailbox::Mailbox>()
                                        .caused_by(trc::location!())?,
                                    presence,
                                )
                                .caused_by(trc::location!())?;
                            }
                            target.commit_point();
                            if is_private_only {
                                will_update_private.push(id);
                            } else {
                                will_update.push(id);
                            }
                        }
                        None => {
                            ctx.response.updated.append(id, None);
                        }
                    }
                    continue 'update;
                }

                match self
                    .mailbox_set_item(object, (document_id, mailbox).into(), &ctx, None)
                    .await?
                {
                    Ok((mut builder, parent)) => {
                        batch
                            .with_account_id(account_id)
                            .with_collection(Collection::Mailbox);

                        if subscription_only {
                            let subscriber = access_token.account_id();
                            let subscribe = builder.changes().unwrap().is_subscribed(subscriber);
                            let subscription_changed =
                                builder.current().unwrap().inner.is_subscribed(subscriber)
                                    != subscribe;

                            if !subscription_changed && metadata_writes.is_none() {
                                ctx.response.updated.append(id, None);
                                continue 'update;
                            }

                            if let Some(prepared) = metadata_writes
                                && let Some(presence) = prepared
                                    .build(document_id, &mut batch, &mut commit)
                                    .caused_by(trc::location!())?
                            {
                                update_mailbox_presence(
                                    &mut batch,
                                    account_id,
                                    document_id,
                                    &mailbox_archive
                                        .to_unarchived::<email::mailbox::Mailbox>()
                                        .caused_by(trc::location!())?,
                                    presence,
                                )
                                .caused_by(trc::location!())?;
                            }
                            if subscription_changed {
                                batch
                                    .with_account_id(account_id)
                                    .with_collection(Collection::Mailbox)
                                    .with_document(document_id);
                                merge_subscription(&mut batch, subscriber, subscribe);
                            }
                            batch.commit_point();
                        } else {
                            if let Some(kinds) = metadata_writes
                                .as_ref()
                                .and_then(|prepared| prepared.shared_kinds())
                                && let Some(mailbox) = builder.changes_mut()
                            {
                                mailbox.set_metadata_kinds(kinds);
                            }
                            if let Some(parent_document_id) = parent.document_id() {
                                batch
                                    .with_document(parent_document_id)
                                    .assert_value(MailboxField::Archive, AssertValue::Some);
                            }

                            batch
                                .with_document(document_id)
                                .custom(builder)
                                .caused_by(trc::location!())?;
                            if let Some(prepared) = metadata_writes {
                                prepared
                                    .build(document_id, &mut batch, &mut commit)
                                    .caused_by(trc::location!())?;
                            }
                            batch.commit_point();
                        }
                        will_update.push(id);
                    }
                    Err(err) => {
                        ctx.response.not_updated.append(id, err);
                        continue 'update;
                    }
                }
            } else {
                ctx.response.not_updated.append(id, SetError::not_found());
            }
        }

        if !batch.is_empty() {
            match self.commit_batch(batch).await {
                Ok(assigned_ids) => {
                    change_id =
                        Some(assigned_ids.last_change_id(account_id, SyncCollection::Email));
                    self.private_metadata_committed(commit, &assigned_ids).await;
                    for id in will_update {
                        ctx.response.updated.append(id, None);
                    }
                }
                Err(err) if err.is_assertion_failure() => {
                    for id in will_update {
                        ctx.response.not_updated.append(
                            id,
                            SetError::forbidden().with_description(
                                "Another process modified this mailbox, please try again.",
                            ),
                        );
                    }
                }
                Err(err) => {
                    return Err(err.caused_by(trc::location!()));
                }
            }
        }
        if !private_batch.is_empty() {
            match self.commit_batch(private_batch).await {
                Ok(assigned_ids) => {
                    has_private_changes = true;
                    self.private_metadata_committed(private_commit, &assigned_ids)
                        .await;
                    for id in will_update_private {
                        ctx.response.updated.append(id, None);
                    }
                }
                Err(err) if err.is_assertion_failure() => {
                    for id in will_update_private {
                        ctx.response.not_updated.append(
                            id,
                            SetError::forbidden().with_description(
                                "Another process modified this mailbox, please try again.",
                            ),
                        );
                    }
                }
                Err(err) => {
                    return Err(err.caused_by(trc::location!()));
                }
            }
        }

        // Process deletions
        let destroy_containers = FlaggedContainers::load(
            self,
            account_id,
            Collection::Mailbox,
            &ctx.will_destroy
                .iter()
                .map(|id| id.document_id())
                .filter(|document_id| {
                    cache
                        .mailbox_by_id(document_id)
                        .is_some_and(|mailbox| !mailbox.metadata_kinds.is_empty())
                })
                .collect(),
        )
        .await
        .caused_by(trc::location!())?;
        for id in ctx.will_destroy {
            match self
                .mailbox_destroy(
                    account_id,
                    id.document_id(),
                    ctx.access_token,
                    on_destroy_remove_emails,
                    Some(&destroy_containers),
                )
                .await?
            {
                Ok(change_id_) => {
                    if change_id_.is_some() {
                        change_id = change_id_;
                    }
                    ctx.response.destroyed.push(id);
                }
                Err(err) => {
                    ctx.response.not_destroyed.append(
                        id,
                        match err {
                            MailboxDestroyError::CannotDestroy => SetError::forbidden()
                                .with_description(
                                    "You are not allowed to delete Inbox, Junk or Trash folders.",
                                ),
                            MailboxDestroyError::Forbidden => SetError::forbidden()
                                .with_description("You are not allowed to delete this mailbox."),
                            MailboxDestroyError::HasChildren => {
                                SetError::new(SetErrorType::MailboxHasChild)
                                    .with_description("Mailbox has at least one children.")
                            }
                            MailboxDestroyError::HasEmails => {
                                SetError::new(SetErrorType::MailboxHasEmail)
                                    .with_description("Mailbox is not empty.")
                            }
                            MailboxDestroyError::NotFound => SetError::not_found(),
                            MailboxDestroyError::AssertionFailed => SetError::forbidden()
                                .with_description(concat!(
                                    "Another process modified a message in this mailbox ",
                                    "while deleting it, please try again."
                                )),
                        },
                    );
                }
            }
        }

        // Write changes
        if change_id.is_some() || has_private_changes {
            ctx.response.new_state = self
                .metadata_state(
                    viewer,
                    account_id,
                    Collection::Mailbox,
                    change_id.map_or(shared_state, State::Exact),
                )
                .await?
                .into();
        }

        Ok(ctx.response)
    }

    #[allow(clippy::blocks_in_conditions)]
    async fn mailbox_set_item(
        &self,
        changes_: Map<'_, MailboxProperty, MailboxValue>,
        update: Option<(u32, Archive<Mailbox>)>,
        ctx: &SetContext<'_>,
        resolver: Option<&CreateResolver<'_>>,
    ) -> trc::Result<
        Result<
            (ObjectIndexBuilder<Archive<Mailbox>, Mailbox>, ParentRef),
            SetError<MailboxProperty>,
        >,
    > {
        // Parse properties
        let mut changes = update
            .as_ref()
            .map(|(_, obj)| obj.inner.clone())
            .unwrap_or_else(|| Mailbox::new(String::new()));
        let mut parent = ParentRef::from_stored(changes.parent_id);
        let mut has_acl_changes = false;
        for (property, mut value) in changes_.into_vec() {
            if let Err(err) = match resolver {
                Some(resolver) => resolver.resolve_self_references(&mut value, 0, false),
                None => ctx.response.resolve_self_references(&mut value, 0, false),
            } {
                return Ok(Err(err));
            };
            match (&property, value) {
                (Key::Property(MailboxProperty::Name), Value::Str(value)) => {
                    let value = value.trim();
                    if !value.is_empty() && value.len() < self.core.email.mailbox_name_max_len {
                        changes.name = value.into();
                    } else {
                        return Ok(Err(SetError::invalid_properties()
                            .with_property(MailboxProperty::Name)
                            .with_description(
                                if !value.is_empty() {
                                    "Mailbox name is too long."
                                } else {
                                    "Mailbox name cannot be empty."
                                }
                                .to_string(),
                            )));
                    }
                }
                (
                    Key::Property(MailboxProperty::ParentId),
                    Value::Element(MailboxValue::Id(value)),
                ) => {
                    let Some(parent_ref) = ParentRef::from_client_id(value, resolver) else {
                        return Ok(Err(SetError::invalid_properties()
                            .with_description("Parent ID does not exist.")));
                    };
                    if let Some(parent_id) = parent_ref.document_id() {
                        if ctx.will_destroy.contains(&value) {
                            return Ok(Err(SetError::will_destroy()
                                .with_description("Parent ID will be destroyed.")));
                        } else if !ctx.mailbox_ids.contains(parent_id) {
                            return Ok(Err(SetError::invalid_properties()
                                .with_description("Parent ID does not exist.")));
                        }
                    }
                    parent = parent_ref;
                }
                (Key::Property(MailboxProperty::ParentId), Value::Null) => {
                    parent = ParentRef::ROOT;
                }
                (Key::Property(MailboxProperty::IsSubscribed), Value::Bool(subscribe)) => {
                    let account_id = ctx
                        .access_token
                        .personal_id(ctx.account_id, Collection::Mailbox);
                    if subscribe {
                        if !changes.subscribers.contains(&account_id) {
                            changes.subscribers.push(account_id);
                        }
                    } else {
                        changes.subscribers.retain(|id| *id != account_id);
                    }
                }
                (
                    Key::Property(MailboxProperty::Role),
                    Value::Element(MailboxValue::Role(role)),
                ) => {
                    changes.role = role;
                }
                (Key::Property(MailboxProperty::Role), Value::Null) => {
                    changes.role = SpecialUse::None;
                }
                (Key::Property(MailboxProperty::SortOrder), Value::Number(value))
                    if let Some(sort_order) = value
                        .as_u64()
                        .and_then(|sort_order| u32::try_from(sort_order).ok())
                        .filter(|sort_order| *sort_order < 1 << 31) =>
                {
                    changes.sort_order = Some(sort_order);
                }
                (Key::Property(MailboxProperty::ShareWith), value) => {
                    match JmapRights::acl_set::<mailbox::Mailbox>(value) {
                        Ok(acls) => {
                            has_acl_changes = true;
                            changes.acls = acls;
                            continue;
                        }
                        Err(err) => {
                            return Ok(Err(err));
                        }
                    }
                }
                (Key::Property(MailboxProperty::Pointer(pointer)), value)
                    if matches!(
                        pointer.first(),
                        Some(JsonPointerItem::Key(Key::Property(
                            MailboxProperty::ShareWith
                        )))
                    ) =>
                {
                    let mut pointer = pointer.iter();
                    pointer.next();

                    match JmapRights::acl_patch::<mailbox::Mailbox>(changes.acls, pointer, value) {
                        Ok(acls) => {
                            has_acl_changes = true;
                            changes.acls = acls;
                            continue;
                        }
                        Err(err) => {
                            return Ok(Err(err));
                        }
                    }
                }

                (Key::Property(MailboxProperty::Id), value) => {
                    if update
                        .as_ref()
                        .map(|(document_id, _)| Id::from(*document_id))
                        .is_none_or(|expected| !crate::matches_id(&value, expected))
                    {
                        return Ok(Err(SetError::invalid_properties()
                            .with_property(MailboxProperty::Id)
                            .with_description("The id property is immutable.".to_string())));
                    }
                }
                _ => {
                    return Ok(Err(SetError::invalid_properties()
                        .with_property(property.into_owned())
                        .with_description("Invalid property or value.".to_string())));
                }
            }
        }

        changes.parent_id = parent.as_stored();

        // Validate depth and circular parent-child relationship. A parent created within
        // this request has no ancestors in storage yet, so there is nothing to walk.
        if !parent.is_pending()
            && update
                .as_ref()
                .is_none_or(|(_, m)| m.inner.parent_id != changes.parent_id)
        {
            let mut mailbox_parent_id = changes.parent_id;
            let current_mailbox_id = update
                .as_ref()
                .map_or(u32::MAX, |(mailbox_id, _)| *mailbox_id + 1);
            let mut success = false;
            for depth in 0..self.core.email.mailbox_max_depth {
                if mailbox_parent_id == current_mailbox_id {
                    return Ok(Err(SetError::invalid_properties()
                        .with_property(MailboxProperty::ParentId)
                        .with_description("Mailbox cannot be a parent of itself.")));
                } else if mailbox_parent_id == 0 {
                    if depth == 0 && ctx.is_shared {
                        return Ok(Err(SetError::forbidden()
                            .with_description("You are not allowed to create root folders.")));
                    }
                    success = true;
                    break;
                }
                let parent_document_id = mailbox_parent_id - 1;

                if let Some(mailbox_) = self
                    .store()
                    .get_value::<Archive<ArchiveBytes>>(ValueKey::archive(
                        ctx.account_id,
                        Collection::Mailbox,
                        parent_document_id,
                    ))
                    .await?
                {
                    let mailbox = mailbox_
                        .unarchive::<email::mailbox::Mailbox>()
                        .caused_by(trc::location!())?;
                    if depth == 0
                        && ctx.is_shared
                        && !mailbox
                            .acls
                            .effective_acl(ctx.access_token)
                            .contains(Acl::CreateChild)
                    {
                        return Ok(Err(SetError::forbidden().with_description(
                            "You are not allowed to create sub mailboxes under this mailbox.",
                        )));
                    }

                    mailbox_parent_id = mailbox.parent_id.into();
                } else if ctx.mailbox_ids.contains(parent_document_id) {
                    // Parent mailbox is probably created within the same request
                    success = true;
                    break;
                } else {
                    return Ok(Err(SetError::invalid_properties()
                        .with_property(MailboxProperty::ParentId)
                        .with_description("Mailbox parent does not exist.")));
                }
            }

            if !success {
                return Ok(Err(SetError::invalid_properties()
                    .with_property(MailboxProperty::ParentId)
                    .with_description(
                        "Mailbox parent-child relationship is too deep.",
                    )));
            }
        }

        let cached_mailboxes = self.get_cached_messages(ctx.account_id).await?;

        let role_change = match &update {
            Some((document_id, current)) => RoleChange::Update {
                document_id: *document_id,
                current: current.inner.role,
                role: changes.role,
            },
            None => RoleChange::Create { role: changes.role },
        };
        if let Err(err) = role_change.validate(&cached_mailboxes) {
            return Ok(Err(SetError::invalid_properties()
                .with_property(MailboxProperty::Role)
                .with_description(err.to_string())));
        }

        // Verify that the mailbox name is unique.
        if !changes.name.is_empty() {
            // Obtain parent mailbox id
            let lower_name = changes.name.to_lowercase();
            if update
                .as_ref()
                .is_none_or(|(_, m)| m.inner.name != changes.name)
                && let Some(parent_cache_id) = parent.cache_id()
                && let Some(existing) = cached_mailboxes.mailboxes.items.iter().find(|m| {
                    m.name.to_lowercase() == lower_name && m.parent_id() == parent_cache_id
                })
            {
                return Ok(Err(SetError::already_exists()
                    .with_existing_id(Id::from(existing.document_id))
                    .with_description(format!(
                        "A mailbox with name '{}' already exists.",
                        changes.name
                    ))));
            }
        } else {
            return Ok(Err(SetError::invalid_properties()
                .with_property(MailboxProperty::Name)
                .with_description("Mailbox name cannot be empty.")));
        }

        // Validate ACLs
        let current = update.map(|(_, current)| current);
        if has_acl_changes
            && !changes.acls.is_empty()
            && let Err(err) = self.acl_validate(&changes.acls).await
        {
            return Ok(Err(err.into()));
        }

        // Validate
        Ok(Ok((
            ObjectIndexBuilder::new()
                .with_changes(changes)
                .with_current_opt(current),
            parent,
        )))
    }
}
