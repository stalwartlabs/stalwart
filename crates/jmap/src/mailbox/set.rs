/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    api::acl::{JmapAcl, JmapRights},
    changes::state::JmapCacheState,
};
use common::{
    Server, auth::AccessToken, sharing::EffectiveAcl, storage::index::ObjectIndexBuilder,
};
#[allow(unused_imports)]
use email::mailbox::{INBOX_ID, JUNK_ID, TRASH_ID, UidMailbox};
use email::{
    cache::{MessageCacheFetch, mailbox::MailboxCacheAccess},
    mailbox::{
        Mailbox,
        destroy::{MailboxDestroy, MailboxDestroyError},
    },
};
use jmap_proto::{
    error::set::{SetError, SetErrorType},
    method::set::{SetRequest, SetResponse},
    object::mailbox::{self, MailboxProperty, MailboxValue},
    references::resolve::ResolveCreatedReference,
    request::IntoValid,
    types::state::State,
};
use jmap_tools::{JsonPointerItem, Key, Map, Value};
use std::future::Future;
use store::{
    ValueKey,
    roaring::RoaringBitmap,
    write::{AlignedBytes, Archive, BatchBuilder, assert::AssertValue},
};
use trc::AddContext;
use types::{
    acl::Acl, collection::Collection, field::MailboxField, id::Id, special_use::SpecialUse,
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
    ) -> impl Future<Output = trc::Result<SetResponse<mailbox::Mailbox>>> + Send;

    fn mailbox_set_item(
        &self,
        changes_: Map<'_, MailboxProperty, MailboxValue>,
        update: Option<(u32, Archive<Mailbox>)>,
        ctx: &SetContext,
    ) -> impl Future<
        Output = trc::Result<
            Result<ObjectIndexBuilder<Mailbox, Mailbox>, SetError<MailboxProperty>>,
        >,
    > + Send;
}

impl MailboxSet for Server {
    #[allow(clippy::blocks_in_conditions)]
    async fn mailbox_set(
        &self,
        mut request: SetRequest<'_, mailbox::Mailbox>,
        access_token: &AccessToken,
    ) -> trc::Result<SetResponse<mailbox::Mailbox>> {
        // Prepare response
        let account_id = request.account_id.document_id();
        let on_destroy_remove_emails = request.arguments.on_destroy_remove_emails.unwrap_or(false);
        let cache = self.get_cached_messages(account_id).await?;
        let mut ctx = SetContext {
            account_id,
            is_shared: access_token.is_shared(account_id),
            access_token,
            response: SetResponse::from_request(&request, self.core.jmap.set_max_objects)?
                .with_state(cache.assert_state(true, &request.if_in_state)?),
            mailbox_ids: RoaringBitmap::from_iter(cache.mailboxes.index.keys()),
            will_destroy: request.unwrap_destroy().into_valid().collect(),
        };
        let mut change_id = None;

        // Process creates
        let mut batch = BatchBuilder::new();
        'create: for (id, object) in request.unwrap_create() {
            let Some(object) = object.into_object() else {
                continue;
            };

            // Validate quota
            if ctx.mailbox_ids.len() >= access_token.object_quota(Collection::Mailbox) as u64 {
                ctx.response.not_created.append(
                    id,
                    SetError::new(SetErrorType::OverQuota).with_description(concat!(
                        "There are too many mailboxes, ",
                        "please delete some before adding a new one."
                    )),
                );
                continue 'create;
            }

            match self.mailbox_set_item(object, None, &ctx).await? {
                Ok(builder) => {
                    batch
                        .with_account_id(account_id)
                        .with_collection(Collection::Mailbox);

                    let parent_id = builder.changes().unwrap().parent_id;
                    if parent_id > 0 {
                        batch
                            .with_document(parent_id - 1)
                            .assert_value(MailboxField::Archive, AssertValue::Some);
                    }

                    let document_id = self
                        .store()
                        .assign_document_ids(account_id, Collection::Mailbox, 1)
                        .await
                        .caused_by(trc::location!())?;

                    batch
                        .with_document(document_id)
                        .custom(builder)
                        .caused_by(trc::location!())?
                        .commit_point();

                    ctx.mailbox_ids.insert(document_id);
                    ctx.response.created(id, document_id);
                }
                Err(err) => {
                    ctx.response.not_created.append(id, err);
                    continue 'create;
                }
            }
        }

        if !batch.is_empty() {
            change_id = self
                .commit_batch(batch)
                .await
                .and_then(|ids| ids.last_change_id(account_id))
                .caused_by(trc::location!())?
                .into();
        }

        // Process updates
        let mut will_update = Vec::with_capacity(request.update.as_ref().map_or(0, |u| u.len()));
        let mut batch = BatchBuilder::new();
        'update: for (id, object) in request.unwrap_update().into_valid() {
            // Make sure id won't be destroyed
            if ctx.will_destroy.contains(&id) {
                ctx.response
                    .not_updated
                    .append(id, SetError::will_destroy());
                continue 'update;
            }
            let Some(object) = object.into_object() else {
                continue 'update;
            };

            // Obtain mailbox
            let document_id = id.document_id();
            if let Some(mailbox) = self
                .store()
                .get_value::<Archive<AlignedBytes>>(ValueKey::archive(
                    account_id,
                    Collection::Mailbox,
                    document_id,
                ))
                .await?
            {
                // Validate ACL
                let mailbox = mailbox
                    .into_deserialized::<email::mailbox::Mailbox>()
                    .caused_by(trc::location!())?;
                if ctx.is_shared {
                    let acl = mailbox.inner.acls.effective_acl(access_token);
                    if !acl.contains(Acl::Modify) {
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

                match self
                    .mailbox_set_item(object, (document_id, mailbox).into(), &ctx)
                    .await?
                {
                    Ok(builder) => {
                        batch
                            .with_account_id(account_id)
                            .with_collection(Collection::Mailbox);

                        let parent_id = builder.changes().unwrap().parent_id;
                        if parent_id > 0 {
                            batch
                                .with_document(parent_id - 1)
                                .assert_value(MailboxField::Archive, AssertValue::Some);
                        }

                        batch
                            .with_document(document_id)
                            .custom(builder)
                            .caused_by(trc::location!())?
                            .commit_point();
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
            match self
                .commit_batch(batch)
                .await
                .and_then(|ids| ids.last_change_id(account_id))
            {
                Ok(change_id_) => {
                    change_id = Some(change_id_);
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

        // Process deletions
        for id in ctx.will_destroy {
            match self
                .mailbox_destroy(
                    account_id,
                    id.document_id(),
                    ctx.access_token,
                    on_destroy_remove_emails,
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
        if let Some(change_id) = change_id {
            ctx.response.new_state = State::Exact(change_id).into();
        }

        Ok(ctx.response)
    }

    #[allow(clippy::blocks_in_conditions)]
    async fn mailbox_set_item(
        &self,
        changes_: Map<'_, MailboxProperty, MailboxValue>,
        update: Option<(u32, Archive<Mailbox>)>,
        ctx: &SetContext<'_>,
    ) -> trc::Result<Result<ObjectIndexBuilder<Mailbox, Mailbox>, SetError<MailboxProperty>>> {
        // Parse properties
        let mut changes = update
            .as_ref()
            .map(|(_, obj)| obj.inner.clone())
            .unwrap_or_else(|| Mailbox::new(String::new()));
        let mut has_acl_changes = false;
        for (property, mut value) in changes_.into_vec() {
            if let Err(err) = ctx.response.resolve_self_references(&mut value) {
                return Ok(Err(err));
            };
            match (&property, value) {
                (Key::Property(MailboxProperty::Name), Value::Str(value)) => {
                    let value = value.trim();
                    if !value.is_empty() && value.len() < self.core.jmap.mailbox_name_max_len {
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
                    let parent_id = value.document_id();
                    if ctx.will_destroy.contains(&value) {
                        return Ok(Err(SetError::will_destroy()
                            .with_description("Parent ID will be destroyed.")));
                    } else if !ctx.mailbox_ids.contains(parent_id) {
                        return Ok(Err(SetError::invalid_properties()
                            .with_description("Parent ID does not exist.")));
                    }
                    changes.parent_id = parent_id + 1;
                }
                (Key::Property(MailboxProperty::ParentId), Value::Null) => {
                    changes.parent_id = 0;
                }
                (Key::Property(MailboxProperty::IsSubscribed), Value::Bool(subscribe)) => {
                    let account_id = ctx.access_token.primary_id();
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
                (Key::Property(MailboxProperty::SortOrder), Value::Number(value)) => {
                    changes.sort_order = Some(value.cast_to_u64() as u32);
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

                _ => {
                    return Ok(Err(SetError::invalid_properties()
                        .with_property(property.into_owned())
                        .with_description("Invalid property or value.".to_string())));
                }
            }
        }

        // Validate depth and circular parent-child relationship
        if update
            .as_ref()
            .is_none_or(|(_, m)| m.inner.parent_id != changes.parent_id)
        {
            let mut mailbox_parent_id = changes.parent_id;
            let current_mailbox_id = update
                .as_ref()
                .map_or(u32::MAX, |(mailbox_id, _)| *mailbox_id + 1);
            let mut success = false;
            for depth in 0..self.core.jmap.mailbox_max_depth {
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
                    .get_value::<Archive<AlignedBytes>>(ValueKey::archive(
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

        // Verify that the mailbox role is unique.
        if update
            .as_ref()
            .is_none_or(|(_, m)| m.inner.role != changes.role)
        {
            if !matches!(changes.role, SpecialUse::None)
                && cached_mailboxes.mailbox_by_role(&changes.role).is_some()
            {
                return Ok(Err(SetError::invalid_properties()
                    .with_property(MailboxProperty::Role)
                    .with_description(format!(
                        "A mailbox with role '{}' already exists.",
                        changes.role.as_str().unwrap_or_default()
                    ))));
            }

            // Role of internal folders cannot be modified
            if update.as_ref().is_some_and(|(document_id, _)| {
                *document_id == INBOX_ID || *document_id == TRASH_ID || *document_id == JUNK_ID
            }) {
                return Ok(Err(SetError::invalid_properties()
                    .with_property(MailboxProperty::Role)
                    .with_description(
                        "You are not allowed to change the role of Inbox, Junk or Trash folders.",
                    )));
            }
        }

        // Verify that the mailbox name is unique.
        if !changes.name.is_empty() {
            // Obtain parent mailbox id
            let lower_name = changes.name.to_lowercase();
            if update
                .as_ref()
                .is_none_or(|(_, m)| m.inner.name != changes.name)
                && cached_mailboxes.mailboxes.items.iter().any(|m| {
                    m.name.to_lowercase() == lower_name
                        && m.parent_id().map_or(0, |id| id + 1) == changes.parent_id
                })
            {
                return Ok(Err(SetError::invalid_properties()
                    .with_property(MailboxProperty::Name)
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

        // Refresh ACLs
        let current = update.map(|(_, current)| current);
        if has_acl_changes {
            if !changes.acls.is_empty()
                && let Err(err) = self.acl_validate(&changes.acls).await
            {
                return Ok(Err(err.into()));
            }

            self.refresh_acls(
                &changes.acls,
                current.as_ref().map(|m| m.inner.acls.as_slice()),
            )
            .await;
        }

        // Validate
        Ok(Ok(ObjectIndexBuilder::new()
            .with_changes(changes)
            .with_current_opt(current)))
    }
}
