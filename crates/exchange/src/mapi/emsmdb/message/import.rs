/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{
    attach_row::push_imported_attachment_properties,
    object_row::{
        MESSAGE_CLASS_KEY, carried_properties, carry_meeting_type, carry_message_class,
        category_names, encode_key,
    },
    save::{MailFlags, SaveMode, SaveTarget, Saved, category_target, write_error},
};
use crate::{
    cache::ExchangeCacheFetch,
    eas::folder_sync::MAX_STATE_ATTEMPTS,
    mail::{AccountCategories, CategoryOutcome, CommitOutcome, FlagOutcome, MailEdits},
    mapi::{
        emsmdb::{
            execute::{RopContext, RopError},
            staged::{RowBaseline, TouchedFlags, TouchedRepresenting},
            state::{MessageObject, mail_container},
        },
        ids::{IdSpace, MapiId},
    },
    store::{
        ExchangeProperty,
        account::ExchangeAccountStore,
        object::{
            ConflictState, ExchangeObject, ExchangeObjectStore, ExchangeObjectWrite, ObjectVersion,
            OwnerStamp,
        },
    },
};
use email::cache::email::MessageCacheAccess;
use exchange_proto::{
    convert::model::MessageContent,
    mapi::{ErrorCode, prop::tags},
};
use store::write::{BatchBuilder, PendingId};
use trc::AddContext;
use types::{
    collection::{Collection, SyncCollection},
    keyword::DRAFT,
};

pub(super) struct ImportSave {
    pub version: ConflictState,
    pub item: Option<u32>,
    pub stored_change: Option<u64>,
}

impl RopContext<'_, '_> {
    pub(super) async fn save_import(
        &mut self,
        message: &MessageObject,
        target: SaveTarget,
        import: ImportSave,
    ) -> Result<Saved, RopError> {
        let container = mail_container(message.folder).ok_or(ErrorCode::NOT_SUPPORTED)?;
        let folder = MapiId::new(IdSpace::Mailbox, container);
        let version = ObjectVersion::Client(import.version);
        match target.base {
            None => {
                let created = self
                    .create_mail(message, container, version, import.item)
                    .await?;
                Ok(Saved {
                    folder,
                    id: created.id,
                    origin: created.origin,
                    row: RowBaseline::Untracked,
                    change: Some(created.change),
                })
            }
            Some(base) => {
                let (origin, change) = self
                    .save_imported(message, container, base, target, version)
                    .await?;
                Ok(Saved {
                    folder,
                    id: base,
                    origin: Some(u64::from(origin)),
                    row: RowBaseline::Untracked,
                    change: Some(change),
                })
            }
        }
    }

    async fn save_imported(
        &mut self,
        message: &MessageObject,
        container: u32,
        base: MapiId,
        target: SaveTarget,
        version: ObjectVersion,
    ) -> Result<(u32, u64), RopError> {
        let account_id = message.mailbox_id;
        let view = self.mailbox(account_id).await?;
        let draft = view
            .messages
            .as_ref()
            .and_then(|messages| messages.message_data(view.email_document(container, base.id)))
            .map(|data| data.keywords & (1 << DRAFT) != 0)
            .ok_or(ErrorCode::OBJECT_DELETED)?;
        if draft {
            let staged = self.staged_message(message)?;
            staged.edit_structure();
            staged.flags_touched = TouchedFlags::ALL;
            staged.categories_touched = true;
            staged.representing_touched = TouchedRepresenting::ALL;
            let (_, origin, _) = self
                .resave_mail(
                    message,
                    container,
                    base,
                    SaveTarget {
                        mode: SaveMode::Force,
                        ..target
                    },
                )
                .await?;
            let document_id = origin
                .and_then(|origin| u32::try_from(origin).ok())
                .ok_or(ErrorCode::OBJECT_DELETED)?;
            let change = self
                .write_import_row(account_id, document_id, version, None)
                .await?;
            return Ok((document_id, change));
        }
        let uploaded = self.staged_message(message)?.content.clone();
        let stored = self.stored_content(message).await?;
        let flags =
            MailFlags::from_props(&uploaded.props, TouchedFlags::ALL).with_verb(&uploaded.props);
        let server = self.request.server;
        let access_token = self.request.access_token;
        let limits = &server.core.email.limits;
        for _ in 0..MAX_STATE_ATTEMPTS {
            let view = self.mailbox(account_id).await?;
            let document_id = view.email_document(container, base.id);
            let messages = view.messages.as_ref().ok_or(ErrorCode::ACCESS_DENIED)?;
            let data = messages
                .email_by_id(&document_id)
                .filter(|item| item.has_mailbox_id(container))
                .and_then(|_| messages.message_data(document_id))
                .ok_or(ErrorCode::OBJECT_DELETED)?;
            let current = messages
                .email_by_id(&document_id)
                .map(|item| messages.custom_keywords(item))
                .unwrap_or_default();
            let categories = category_target(
                category_names(&uploaded.props),
                AccountCategories::new(&view.exchange).resolve(current),
            );
            let mut edits = MailEdits::new(account_id);
            let changed = match &categories {
                Some(names) => match edits.set_categories(
                    limits,
                    document_id,
                    &data,
                    flags.edit(),
                    names,
                    AccountCategories::new(&view.exchange),
                )? {
                    CategoryOutcome::Changed | CategoryOutcome::Renamed => true,
                    CategoryOutcome::Unchanged => false,
                    CategoryOutcome::KeywordLimit | CategoryOutcome::InvalidName => {
                        return Err(RopError::Code(ErrorCode::ERROR));
                    }
                },
                None => match edits.set_flags(limits, document_id, &data, flags.edit())? {
                    FlagOutcome::Changed => true,
                    FlagOutcome::Unchanged => false,
                    FlagOutcome::KeywordLimit => return Err(RopError::Code(ErrorCode::ERROR)),
                },
            };
            if changed {
                match edits
                    .commit(server, access_token, self.session_id())
                    .await?
                {
                    CommitOutcome::Committed(_) => self.invalidate_mailbox(),
                    CommitOutcome::Conflict => {
                        self.invalidate_mailbox();
                        continue;
                    }
                }
            }
            return self
                .write_import_row(account_id, document_id, version, Some((&uploaded, &stored)))
                .await
                .map(|change| (document_id, change));
        }
        Err(RopError::Code(ErrorCode::OBJECT_MODIFIED))
    }

    pub(in crate::mapi::emsmdb) async fn write_import_row(
        &mut self,
        account_id: u32,
        document_id: u32,
        version: ObjectVersion,
        contents: Option<(&MessageContent, &MessageContent)>,
    ) -> Result<u64, RopError> {
        let server = self.request.server;
        let owner = server
            .exchange_quota_owner(self.request.access_token, account_id)
            .await?;
        let max_size = server.core.exchange.max_object_size;
        for _ in 0..MAX_STATE_ATTEMPTS {
            let view = self.mailbox(account_id).await?;
            let thread_id = view
                .messages
                .as_ref()
                .and_then(|messages| messages.message_data(document_id))
                .map(|data| data.thread_id)
                .ok_or(ErrorCode::OBJECT_DELETED)?;
            let previous = server
                .exchange_object(account_id, Collection::Email, document_id)
                .await
                .caused_by(trc::location!())?;
            let current = match &previous {
                Some(previous) => previous.deserialize::<ExchangeObject>()?,
                None => ExchangeObject::default(),
            };
            let next = match contents {
                Some((uploaded, stored)) => ExchangeObject {
                    properties: imported_properties(
                        account_id, uploaded, stored, &current, max_size,
                    ),
                    conflict: None,
                },
                None => current,
            };
            let mut batch = BatchBuilder::new();
            ExchangeObjectWrite {
                owner,
                collection: Collection::Email,
                document_id: PendingId::Assigned(document_id),
                stamp: OwnerStamp::Email { thread_id },
                version: version.clone(),
                previous: previous.as_ref(),
                next: Some(next),
                max_size,
            }
            .build(&mut batch)
            .map_err(write_error)?;
            match server.commit_batch(batch).await {
                Ok(assigned) => {
                    server.mark_exchange_stale(account_id);
                    self.invalidate_mailbox();
                    return assigned
                        .change_id(account_id, SyncCollection::Email)
                        .ok_or(RopError::Code(ErrorCode::ERROR));
                }
                Err(err) if err.is_assertion_failure() => {
                    self.invalidate_mailbox();
                }
                Err(err) => return Err(write_error(err)),
            }
        }
        Err(RopError::Code(ErrorCode::OBJECT_MODIFIED))
    }
}

fn imported_properties(
    account_id: u32,
    uploaded: &MessageContent,
    stored: &MessageContent,
    current: &ExchangeObject,
    max_size: usize,
) -> Vec<ExchangeProperty> {
    let mut properties = carried_properties(&uploaded.props, |key| {
        current.property(&encode_key(key)).is_some() || stored.props.get_any(key).is_none()
    });
    carry_meeting_type(&mut properties, &uploaded.props, current);
    let implied = match current.property(&MESSAGE_CLASS_KEY) {
        Some(_) => None,
        None => stored.props.text(tags::MESSAGE_CLASS.id()),
    };
    carry_message_class(&mut properties, &uploaded.props, implied);
    push_imported_attachment_properties(
        account_id,
        uploaded,
        stored,
        current,
        max_size,
        &mut properties,
    );
    properties
}
