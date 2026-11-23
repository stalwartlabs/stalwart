/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{
    changes::{ItemEntry, OwnChanges},
    note_write::{NoteResult, NoteTarget, NoteWriter},
    state::ClientView,
};
use crate::eas::{
    context::EasContext,
    convert::{
        body::BodyChoice,
        email::{MailFlags, MailSource, MeetingPart, ParsedMeeting},
        flag::{FlagKeys, MailRow, StoredFlags},
    },
    folder_sync::MAX_STATE_ATTEMPTS,
};
use crate::{
    cache::ExchangeCacheFetch,
    folders::ContainerClass,
    mail::{AccountCategories, CategoryOutcome, CommitOutcome, FlagEdit, FlagOutcome, MailEdits},
    store::{
        QuotaOwner,
        account::ExchangeAccountStore,
        eas::EasClientId,
        object::{ExchangeObject, ExchangeObjectStore, OwnerStamp},
    },
};
use common::{
    MessageStoreCache, Server, cache::exchange::ExchangeAccountCache, storage::blob::FetchedBlob,
};
use email::{
    cache::{MessageCacheFetch, email::MessageCacheAccess, mailbox::MailboxCacheAccess},
    message::metadata::MetadataRow,
};
use exchange_proto::{
    common::token::TokenBuf,
    convert::ical::eas::MeetingHistory,
    eas::{
        commands::{
            appdata::{
                ApplicationData,
                email::{Email, EmailFlag},
                note::Note,
            },
            find::FindMailProperties,
            sync::{ClientCommand, SyncOptions},
        },
        status::SyncStatus,
        tokens::ProtocolVersion,
        types::{Class, EasDateTime},
        wbxml::WbxmlLimits,
    },
    ids::eas::EasServerId,
};
use smallvec::SmallVec;
use std::{borrow::Cow, sync::Arc};
use store::{ValueKey, roaring::RoaringBitmap};
use trc::AddContext;
use types::{
    collection::Collection,
    field::EmailField,
    keyword::{ANSWERED, FLAGGED, FORWARDED},
    special_use::SpecialUse,
};

const FLAG_STATUS_CLEARED: u8 = 0;
const FLAG_STATUS_COMPLETE: u8 = 1;
const FLAG_STATUS_ACTIVE: u8 = 2;
const FLAGGED_BIT: u32 = 1 << FLAGGED;
const SEEN_BIT: u32 = 1 << types::keyword::SEEN;
const ANSWERED_BIT: u32 = 1 << ANSWERED;
const FORWARDED_BIT: u32 = 1 << FORWARDED;

#[derive(Debug, Clone, Copy)]
pub struct MailTarget {
    pub mailbox_id: u32,
    pub trash_id: Option<u32>,
    pub deletes_as_moves: bool,
}

#[derive(Debug)]
pub enum ItemReply {
    Add {
        class: Option<Class>,
        client_id: String,
        server_id: Option<TokenBuf>,
        status: SyncStatus,
        uid: Option<String>,
    },
    Change {
        server_id: String,
        instance_id: Option<EasDateTime>,
        status: SyncStatus,
    },
    Delete {
        server_id: String,
        instance_id: Option<EasDateTime>,
        status: SyncStatus,
    },
    Fetch {
        server_id: String,
        document_id: Option<u32>,
    },
}

pub struct ClientResult {
    pub cache: Arc<MessageStoreCache>,
    pub replies: Vec<ItemReply>,
    pub own: OwnChanges,
    pub client_ids: Vec<EasClientId>,
}

fn is_valid_change(email: &Email<'_>) -> bool {
    email.sender.is_none()
        && email.conversation_id.is_none()
        && email.conversation_index.is_none()
        && email.um_caller_id.is_none()
        && email.um_user_notes.is_none()
        && email.flag.as_ref().is_none_or(is_valid_flag)
}

fn is_valid_flag(flag: &EmailFlag<'_>) -> bool {
    let ordered = |start: Option<EasDateTime>, due: Option<EasDateTime>| {
        start.zip(due).is_none_or(|(start, due)| start <= due)
    };
    let dated = flag.start_date.is_some()
        || flag.due_date.is_some()
        || flag.date_completed.is_some()
        || flag.complete_time.is_some();
    matches!(
        flag.status,
        None | Some(FLAG_STATUS_CLEARED | FLAG_STATUS_COMPLETE | FLAG_STATUS_ACTIVE)
    ) && (flag.reminder_set != Some(true) || flag.reminder_time.is_some())
        && flag.start_date.is_some() == flag.utc_start_date.is_some()
        && flag.due_date.is_some() == flag.utc_due_date.is_some()
        && ordered(flag.start_date, flag.due_date)
        && ordered(flag.utc_start_date, flag.utc_due_date)
        && (flag.status != Some(FLAG_STATUS_ACTIVE) || flag.flag_type.is_some() || dated)
}

pub struct LoadedMail {
    pub document_id: u32,
    pub thread_id: u32,
    pub received_at: u64,
    pub body: BodyChoice,
    body_shown: bool,
    part: Option<BodyChoice>,
    pub(super) meeting: Option<Box<ParsedMeeting>>,
    body_loaded: bool,
    row: MetadataRow,
    blob: Option<FetchedBlob>,
}

enum Planned {
    Change(u32),
    Delete(u32),
}

impl MailTarget {
    fn held_id(&self, server_id: &str) -> Option<u32> {
        EasServerId::decode(server_id)
            .filter(|id| id.container == self.mailbox_id)
            .map(|id| id.id)
    }

    pub(super) fn document_id(&self, cache: &MessageStoreCache, server_id: &str) -> Option<u32> {
        cache
            .email_by_id(&self.held_id(server_id)?)
            .filter(|message| message.has_mailbox_id(self.mailbox_id))
            .map(|message| message.document_id())
    }

    pub fn entries(&self, cache: &MessageStoreCache) -> Vec<ItemEntry> {
        cache
            .in_mailbox(self.mailbox_id)
            .map(|message| ItemEntry {
                document_id: message.document_id(),
                change_id: message.change_id(),
                received_at: message.received_at(),
                size: message.size(),
            })
            .collect()
    }
}

pub struct MailCommands<'x> {
    pub target: MailTarget,
    pub class: Class,
    pub commands: &'x [ClientCommand<'x>],
    pub replayed: &'x [EasClientId],
}

pub async fn apply_mail_commands(
    server: &Server,
    ctx: &EasContext<'_>,
    mut cache: Arc<MessageStoreCache>,
    request: MailCommands<'_>,
    view: &mut ClientView,
) -> trc::Result<ClientResult> {
    let MailCommands {
        target,
        class,
        commands,
        replayed,
    } = request;
    if commands.is_empty() {
        return Ok(ClientResult {
            cache,
            replies: Vec::new(),
            own: OwnChanges::default(),
            client_ids: Vec::new(),
        });
    }

    let notes = match class {
        Class::Notes => {
            let notes =
                NoteWriter::apply(server, ctx, target, replayed, &cache, commands, view).await?;
            if notes.wrote {
                cache = server.get_cached_messages(ctx.account_id).await?;
            }
            notes
        }
        _ => NoteResult::default(),
    };

    let mut replies = Vec::with_capacity(commands.len());
    let mut planned = Vec::with_capacity(commands.len());
    let mut exchange: Option<Arc<ExchangeAccountCache>> = None;
    let mut owner: Option<QuotaOwner> = None;
    let mut flag_keys: Option<FlagKeys> = None;
    for _ in 0..MAX_STATE_ATTEMPTS {
        replies.clear();
        planned.clear();
        let mut edits = MailEdits::new(ctx.account_id);
        let mut edited = RoaringBitmap::new();
        for (slot, command) in commands.iter().enumerate() {
            match command {
                ClientCommand::Add { .. } if class == Class::Notes => {}
                ClientCommand::Change {
                    server_id, data, ..
                } if class == Class::Notes => {
                    let status = match notes.targets.get(slot).copied().unwrap_or_default() {
                        NoteTarget::Failed(status) => Some(status),
                        NoteTarget::Untouched => Some(SyncStatus::CONVERSION_ERROR),
                        NoteTarget::Categories { document_id, .. }
                            if edited.contains(document_id) =>
                        {
                            Some(SyncStatus::CONFLICT)
                        }
                        NoteTarget::Categories {
                            document_id,
                            replaced,
                        } => {
                            let names = match data.parse(
                                Class::Notes,
                                ctx.version,
                                &WbxmlLimits::DEFAULT,
                            ) {
                                Ok(ApplicationData::Note(note)) => note
                                    .categories
                                    .map(|categories| categories.0)
                                    .unwrap_or_default(),
                                _ => Vec::new(),
                            };
                            let names = names
                                .iter()
                                .map(|name| name.as_ref())
                                .collect::<SmallVec<[&str; 8]>>();
                            match cache.message_data(document_id) {
                                Some(data) => {
                                    let exchange: &ExchangeAccountCache = match exchange {
                                        Some(ref exchange) => exchange,
                                        None => exchange.insert(
                                            server.get_cached_exchange(ctx.account_id).await?,
                                        ),
                                    };
                                    match edits.set_categories(
                                        &server.core.email.limits,
                                        document_id,
                                        &data,
                                        FlagEdit::default(),
                                        &names,
                                        AccountCategories::new(exchange),
                                    )? {
                                        CategoryOutcome::Changed
                                        | CategoryOutcome::Renamed
                                        | CategoryOutcome::Unchanged => {
                                            if !replaced && edited.insert(document_id) {
                                                planned.push(Planned::Change(document_id));
                                            }
                                            None
                                        }
                                        CategoryOutcome::KeywordLimit
                                        | CategoryOutcome::InvalidName => {
                                            Some(SyncStatus::CONVERSION_ERROR)
                                        }
                                    }
                                }
                                None => Some(SyncStatus::OBJECT_NOT_FOUND),
                            }
                        }
                    };
                    if let Some(status) = status {
                        replies.push(ItemReply::Change {
                            server_id: server_id.to_string(),
                            instance_id: None,
                            status,
                        });
                    }
                }
                ClientCommand::Add {
                    client_id, class, ..
                } => replies.push(ItemReply::Add {
                    class: *class,
                    client_id: client_id.to_string(),
                    server_id: None,
                    status: SyncStatus::CONVERSION_ERROR,
                    uid: None,
                }),
                ClientCommand::Fetch { server_id } => replies.push(ItemReply::Fetch {
                    server_id: server_id.to_string(),
                    document_id: target.document_id(&cache, server_id),
                }),
                ClientCommand::Change {
                    server_id, data, ..
                } => {
                    let status = match (
                        target.document_id(&cache, server_id),
                        data.parse(Class::Email, ctx.version, &WbxmlLimits::DEFAULT),
                    ) {
                        (_, Ok(ApplicationData::Email(email))) if !is_valid_change(&email) => {
                            Some(SyncStatus::CONVERSION_ERROR)
                        }
                        (Some(document_id), _) if edited.contains(document_id) => {
                            Some(SyncStatus::CONFLICT)
                        }
                        (Some(document_id), Ok(ApplicationData::Email(email))) => {
                            let edit = FlagEdit {
                                read: email.read,
                                flagged: email.flag.as_ref().map(|flag| {
                                    flag.status
                                        .is_some_and(|status| status == FLAG_STATUS_ACTIVE)
                                }),
                                ..Default::default()
                            };
                            let limits = &server.core.email.limits;
                            let max_size = server.core.exchange.max_object_size;
                            match cache.message_data(document_id) {
                                None => Some(SyncStatus::OBJECT_NOT_FOUND),
                                Some(data) => {
                                    let row = match &email.flag {
                                        Some(flag) => {
                                            let exchange: &ExchangeAccountCache = match exchange {
                                                Some(ref exchange) => exchange,
                                                None => exchange.insert(
                                                    server
                                                        .get_cached_exchange(ctx.account_id)
                                                        .await?,
                                                ),
                                            };
                                            let mut row = MailRow::load(
                                                server,
                                                exchange,
                                                ctx.account_id,
                                                document_id,
                                            )
                                            .await?;
                                            flag_keys
                                                .get_or_insert_with(FlagKeys::new)
                                                .write(&mut row.next, flag)
                                                .then_some(row)
                                        }
                                        None => None,
                                    };
                                    let applied = if row
                                        .as_ref()
                                        .is_some_and(|row| row.next.exceeds(max_size))
                                    {
                                        None
                                    } else if let Some(categories) = &email.categories {
                                        let exchange: &ExchangeAccountCache = match exchange {
                                            Some(ref exchange) => exchange,
                                            None => exchange.insert(
                                                server.get_cached_exchange(ctx.account_id).await?,
                                            ),
                                        };
                                        let names = categories
                                            .0
                                            .iter()
                                            .map(|name| name.as_ref())
                                            .collect::<SmallVec<[&str; 8]>>();
                                        match edits.set_categories(
                                            limits,
                                            document_id,
                                            &data,
                                            edit,
                                            &names,
                                            AccountCategories::new(exchange),
                                        )? {
                                            CategoryOutcome::Changed => Some(true),
                                            CategoryOutcome::Renamed
                                            | CategoryOutcome::Unchanged => Some(false),
                                            CategoryOutcome::KeywordLimit
                                            | CategoryOutcome::InvalidName => None,
                                        }
                                    } else {
                                        match edits.set_flags(limits, document_id, &data, edit)? {
                                            FlagOutcome::Changed => Some(true),
                                            FlagOutcome::Unchanged => Some(false),
                                            FlagOutcome::KeywordLimit => None,
                                        }
                                    };
                                    match applied {
                                        Some(logged) => {
                                            if let Some(mut row) = row {
                                                let owner = match owner {
                                                    Some(owner) => owner,
                                                    None => *owner.insert(
                                                        server
                                                            .exchange_quota_owner(
                                                                &ctx.access_token,
                                                                ctx.account_id,
                                                            )
                                                            .await?,
                                                    ),
                                                };
                                                edits.write_object(row.write(
                                                    owner,
                                                    document_id,
                                                    if logged {
                                                        OwnerStamp::Logged
                                                    } else {
                                                        OwnerStamp::Email {
                                                            thread_id: data.thread_id,
                                                        }
                                                    },
                                                    max_size,
                                                ))?;
                                            }
                                            edited.insert(document_id);
                                            planned.push(Planned::Change(document_id));
                                            None
                                        }
                                        None => Some(SyncStatus::CONVERSION_ERROR),
                                    }
                                }
                            }
                        }
                        (Some(_), _) => Some(SyncStatus::CONVERSION_ERROR),
                        (None, _) => Some(SyncStatus::OBJECT_NOT_FOUND),
                    };
                    if let Some(status) = status {
                        replies.push(ItemReply::Change {
                            server_id: server_id.to_string(),
                            instance_id: None,
                            status,
                        });
                    }
                }
                ClientCommand::Delete { server_id, .. } => {
                    let data = target
                        .document_id(&cache, server_id)
                        .and_then(|document_id| {
                            cache
                                .message_data(document_id)
                                .map(|data| (document_id, data))
                        });
                    let Some((document_id, data)) = data else {
                        if let Some(document_id) = target
                            .held_id(server_id)
                            .filter(|document_id| view.held.contains(*document_id))
                            && edited.insert(document_id)
                        {
                            planned.push(Planned::Delete(document_id));
                            continue;
                        }
                        replies.push(ItemReply::Delete {
                            server_id: server_id.to_string(),
                            instance_id: None,
                            status: SyncStatus::OBJECT_NOT_FOUND,
                        });
                        continue;
                    };
                    if !edited.insert(document_id) {
                        replies.push(ItemReply::Delete {
                            server_id: server_id.to_string(),
                            instance_id: None,
                            status: SyncStatus::CONFLICT,
                        });
                        continue;
                    }
                    let removed = match target.trash_id.filter(|trash_id| {
                        target.deletes_as_moves && *trash_id != target.mailbox_id
                    }) {
                        Some(trash_id) => {
                            edits.move_to(document_id, data, target.mailbox_id, trash_id)?
                        }
                        None => edits.remove_from(document_id, data, target.mailbox_id)?,
                    };
                    if removed {
                        planned.push(Planned::Delete(document_id));
                    } else {
                        replies.push(ItemReply::Delete {
                            server_id: server_id.to_string(),
                            instance_id: None,
                            status: SyncStatus::OBJECT_NOT_FOUND,
                        });
                    }
                }
            }
        }

        match edits
            .commit(server, &ctx.access_token, ctx.session.session_id)
            .await?
        {
            CommitOutcome::Committed(change_id) => {
                let mut own = OwnChanges {
                    documents: notes.own,
                    change_id: change_id.max(notes.change_id),
                };
                for planned in &planned {
                    match planned {
                        Planned::Change(document_id) => {
                            own.documents.insert(*document_id);
                        }
                        Planned::Delete(document_id) => {
                            if view.held.remove(*document_id) {
                                view.removed.insert(*document_id);
                            }
                        }
                    }
                }
                let cache = server.get_cached_messages(ctx.account_id).await?;
                replies.extend(notes.replies);
                return Ok(ClientResult {
                    cache,
                    replies,
                    own,
                    client_ids: notes.client_ids,
                });
            }
            CommitOutcome::Conflict => {
                cache = server.get_cached_messages(ctx.account_id).await?;
                exchange = None;
            }
        }
    }

    Err(trc::StoreEvent::AssertValueFailed
        .into_err()
        .details("Too many conflicts applying Exchange ActiveSync changes.")
        .caused_by(trc::location!()))
}

pub async fn load_mail(
    server: &Server,
    account_id: u32,
    cache: &MessageStoreCache,
    document_id: u32,
    options: Option<&SyncOptions>,
) -> trc::Result<Option<LoadedMail>> {
    let Some(message) = cache.email_by_id(&document_id) else {
        return Ok(None);
    };
    let Some(row) = server
        .store()
        .get_value::<MetadataRow>(ValueKey::immutable(
            account_id,
            Collection::Email,
            document_id,
            EmailField::Metadata,
        ))
        .await
        .caused_by(trc::location!())?
    else {
        return Ok(None);
    };
    let meta = row.unarchive().caused_by(trc::location!())?;
    let body = BodyChoice::select(options, BodyChoice::is_smime(meta));
    let part = BodyChoice::select_part(options);
    let range = match (
        body.blob_range(meta),
        part.and_then(|part| part.blob_range(meta)),
    ) {
        (Some(body), Some(part)) => Some(body.start.min(part.start)..body.end.max(part.end)),
        (body, part) => body.or(part),
    };
    let body_loaded = range.is_some();
    let meeting = MeetingPart::find(meta, server.core.groupware.itip_inbound_max_ical_size);
    let range = match meeting.map(|meeting| meeting.blob_end()) {
        Some(end) => Some(range.map_or(0..end, |range| 0..range.end.max(end))),
        None => range,
    };
    let blob = match range {
        Some(range) => server
            .fetch_blob(&meta.blob_hash(), range, Some(meta.size() as u64))
            .await
            .caused_by(trc::location!())?,
        None => None,
    };
    let meeting = match (meeting, blob.as_deref()) {
        (Some(part), Some(blob)) => {
            let headers = row.raw_headers().caused_by(trc::location!())?;
            let ical = part.ical(meta, meta.raw_message(Some(&headers), blob));
            ical.map(|ical| {
                Box::new(ParsedMeeting {
                    part,
                    ical,
                    history: MeetingHistory::Current,
                    inflated_headers: match headers {
                        Cow::Owned(headers) => Some(headers),
                        Cow::Borrowed(_) => None,
                    },
                })
            })
        }
        _ => None,
    };
    Ok(Some(LoadedMail {
        document_id,
        thread_id: message.thread_id(),
        received_at: message.received_at(),
        body,
        body_shown: BodyChoice::shows_body(options),
        part,
        meeting,
        body_loaded,
        row,
        blob,
    }))
}

pub fn mail_flags<'a>(
    cache: &'a MessageStoreCache,
    exchange: &'a ExchangeAccountCache,
    stored: &'a StoredFlags,
    document_id: u32,
) -> Option<MailFlags<'a>> {
    let message = cache.email_by_id(&document_id)?;
    let keywords = message.keywords();
    Some(MailFlags {
        read: keywords & SEEN_BIT != 0,
        flagged: keywords & FLAGGED_BIT != 0,
        answered: keywords & ANSWERED_BIT != 0,
        forwarded: keywords & FORWARDED_BIT != 0,
        stored: stored.get(document_id),
        categories: cache.custom_keywords(message),
        names: AccountCategories::new(exchange),
    })
}

pub async fn mail_class(
    server: &Server,
    account_id: u32,
    cache: &MessageStoreCache,
    exchange: &ExchangeAccountCache,
    mailbox_id: u32,
) -> trc::Result<Class> {
    if cache
        .mailbox_by_role(&SpecialUse::Memos)
        .is_some_and(|mailbox| mailbox.document_id == mailbox_id)
    {
        return Ok(Class::Notes);
    }
    let typed_by_role = cache.mailbox_by_id(&mailbox_id).is_some_and(|mailbox| {
        matches!(
            mailbox.role,
            SpecialUse::Inbox | SpecialUse::Drafts | SpecialUse::Sent | SpecialUse::Trash
        )
    });
    if typed_by_role || !exchange.has_object(Collection::Mailbox, mailbox_id) {
        return Ok(Class::Email);
    }
    let Some(archive) = server
        .exchange_object(account_id, Collection::Mailbox, mailbox_id)
        .await
        .caused_by(trc::location!())?
    else {
        return Ok(Class::Email);
    };
    let sticky = archive
        .unarchive::<ExchangeObject>()?
        .property(&ContainerClass::property_key())
        .and_then(ContainerClass::from_property_value)
        .is_some_and(|class| class == ContainerClass::StickyNote);
    Ok(if sticky { Class::Notes } else { Class::Email })
}

impl LoadedMail {
    pub fn email<'a>(
        &'a self,
        flags: MailFlags<'a>,
        owner: &[String],
        version: ProtocolVersion,
    ) -> trc::Result<Email<'a>> {
        self.render(|source| {
            source.email(
                flags,
                self.body_shown.then_some(&self.body),
                self.part.as_ref(),
                owner,
                version,
            )
        })
    }

    pub fn find_properties<'a>(
        &'a self,
        flags: MailFlags<'a>,
        draft: bool,
    ) -> trc::Result<FindMailProperties<'a>> {
        self.render(|source| source.find(flags, draft))
    }

    pub fn note<'a>(&'a self, flags: MailFlags<'a>) -> trc::Result<Note<'a>> {
        self.render(|source| source.note(flags, &self.body))
    }

    fn render<'a, T>(&'a self, f: impl for<'r> FnOnce(&MailSource<'a, 'r>) -> T) -> trc::Result<T> {
        let meta = self.row.unarchive().caused_by(trc::location!())?;
        let headers = match self
            .meeting
            .as_deref()
            .and_then(|meeting| meeting.inflated_headers.as_deref())
        {
            Some(headers) => Cow::Borrowed(headers),
            None => self.row.raw_headers().caused_by(trc::location!())?,
        };
        let raw = self
            .blob
            .as_deref()
            .map(|blob| meta.raw_message(Some(&headers), blob));
        let source = MailSource {
            document_id: self.document_id,
            thread_id: self.thread_id,
            received_at: self.received_at,
            meta,
            headers: &headers,
            raw: raw.filter(|_| self.body_loaded),
            meeting: self.meeting.as_deref(),
        };
        Ok(f(&source))
    }
}
