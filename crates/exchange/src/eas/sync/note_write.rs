/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{
    email::{ItemReply, MailTarget},
    groupware_write::store_status,
    server_id,
    state::ClientView,
};
use crate::{
    cache::ExchangeCacheFetch,
    eas::{
        context::EasContext,
        convert::{
            body::{TextKind, incoming_body},
            email::MESSAGE_CLASS_NOTE,
        },
    },
    mail::{AccountCategories, CategoryOutcome, fetch_raw_message},
    store::{
        account::ExchangeAccountStore,
        category::SpellingChanges,
        eas::EasClientId,
        object::{
            CreatedEmail, ExchangeObject, ExchangeObjectStore, ReplacedEmail, StoredPlacement,
        },
    },
};
use common::{MessageStoreCache, Server, cache::exchange::ExchangeAccountCache};
use email::{
    cache::email::MessageCacheAccess,
    message::ingest::{IngestEmail, IngestSource},
};
use exchange_proto::eas::{
    commands::{
        appdata::{ApplicationData, RawApplicationData, base::Body, note::Note},
        sync::ClientCommand,
    },
    status::SyncStatus,
    types::Class,
    wbxml::WbxmlLimits,
};
use mail_builder::MessageBuilder;
use mail_parser::{Message, MessageParser, PartKind};
use smallvec::SmallVec;
use std::{borrow::Cow, sync::Arc};
use store::roaring::RoaringBitmap;
use trc::{EventType, LimitEvent, MessageIngestEvent};
use types::{collection::Collection, keyword::Keyword};

type Outcome<T> = trc::Result<Result<T, SyncStatus>>;

#[derive(Debug, Clone, Copy, Default)]
pub enum NoteTarget {
    #[default]
    Untouched,
    Failed(SyncStatus),
    Categories {
        document_id: u32,
        replaced: bool,
    },
}

#[derive(Default)]
pub struct NoteResult {
    pub replies: Vec<ItemReply>,
    pub targets: Vec<NoteTarget>,
    pub own: RoaringBitmap,
    pub change_id: Option<u64>,
    pub client_ids: Vec<EasClientId>,
    pub wrote: bool,
}

struct NoteBody<'x> {
    kind: TextKind,
    text: Cow<'x, str>,
}

impl NoteBody<'_> {
    fn same_content(&self, other: &NoteBody<'_>) -> bool {
        self.kind == other.kind && text_content(&self.text).eq(text_content(&other.text))
    }
}

fn text_content(text: &str) -> impl Iterator<Item = u8> + '_ {
    text.trim_end_matches(['\r', '\n'])
        .bytes()
        .filter(|byte| *byte != b'\r')
}

pub(super) struct NoteWriter<'x> {
    server: &'x Server,
    ctx: &'x EasContext<'x>,
    target: MailTarget,
    replayed: &'x [EasClientId],
    exchange: Arc<ExchangeAccountCache>,
    edited: RoaringBitmap,
    deleted: RoaringBitmap,
    result: NoteResult,
}

impl<'x> NoteWriter<'x> {
    pub async fn apply(
        server: &'x Server,
        ctx: &'x EasContext<'x>,
        target: MailTarget,
        replayed: &'x [EasClientId],
        cache: &MessageStoreCache,
        commands: &[ClientCommand<'_>],
        view: &mut ClientView,
    ) -> trc::Result<NoteResult> {
        if !commands.iter().any(|command| {
            matches!(
                command,
                ClientCommand::Add { .. } | ClientCommand::Change { .. }
            )
        }) {
            return Ok(NoteResult::default());
        }
        let deleted = commands
            .iter()
            .filter_map(|command| match command {
                ClientCommand::Delete { server_id, .. } => target.document_id(cache, server_id),
                _ => None,
            })
            .collect();
        let mut writer = NoteWriter {
            server,
            ctx,
            target,
            replayed,
            exchange: server.get_cached_exchange(ctx.account_id).await?,
            edited: RoaringBitmap::new(),
            deleted,
            result: NoteResult {
                targets: vec![NoteTarget::Untouched; commands.len()],
                ..Default::default()
            },
        };
        for (slot, command) in commands.iter().enumerate() {
            match command {
                ClientCommand::Add {
                    client_id,
                    class,
                    data,
                    ..
                } => {
                    let outcome = match class {
                        Some(class) if *class != Class::Notes => Err(SyncStatus::CONVERSION_ERROR),
                        _ => writer.add(cache, client_id, data, view).await?,
                    };
                    let reply = match outcome {
                        Ok(document_id) => ItemReply::Add {
                            class: *class,
                            client_id: client_id.to_string(),
                            server_id: Some(server_id(target.mailbox_id, document_id)),
                            status: SyncStatus::SUCCESS,
                            uid: None,
                        },
                        Err(status) => ItemReply::Add {
                            class: *class,
                            client_id: client_id.to_string(),
                            server_id: None,
                            status,
                            uid: None,
                        },
                    };
                    writer.result.replies.push(reply);
                }
                ClientCommand::Change {
                    server_id, data, ..
                } => {
                    let target = match writer.change(cache, server_id, data, view).await? {
                        Ok(target) => target,
                        Err(status) => NoteTarget::Failed(status),
                    };
                    if let Some(entry) = writer.result.targets.get_mut(slot) {
                        *entry = target;
                    }
                }
                ClientCommand::Delete { .. } | ClientCommand::Fetch { .. } => {}
            }
        }
        Ok(writer.result)
    }

    async fn add(
        &mut self,
        cache: &MessageStoreCache,
        client_id: &str,
        data: &RawApplicationData<'_>,
        view: &mut ClientView,
    ) -> Outcome<u32> {
        let document_id = match self
            .replayed
            .iter()
            .find(|known| known.client_id == client_id)
        {
            Some(known) => {
                if let Some(message) = cache.email_by_id(&known.server_id) {
                    self.result.change_id = self.result.change_id.max(Some(message.change_id()));
                }
                known.server_id
            }
            None => match self.create(data).await? {
                Ok(document_id) => document_id,
                Err(status) => return Ok(Err(status)),
            },
        };
        view.held.insert(document_id);
        self.result.own.insert(document_id);
        self.result.client_ids.push(EasClientId {
            client_id: client_id.to_string(),
            server_id: document_id,
        });
        Ok(Ok(document_id))
    }

    async fn create(&mut self, data: &RawApplicationData<'_>) -> Outcome<u32> {
        let Some(note) = self.parse(data) else {
            return Ok(Err(SyncStatus::CONVERSION_ERROR));
        };
        let body = note
            .body
            .as_ref()
            .and_then(note_body)
            .unwrap_or_else(empty_body);
        let Some(raw) = compose(note.subject.as_deref().unwrap_or_default(), &body) else {
            return Ok(Err(SyncStatus::CONVERSION_ERROR));
        };
        let mut keywords = vec![Keyword::Seen];
        let mut spellings = SpellingChanges::default();
        if let Some(categories) = &note.categories {
            let names = categories
                .0
                .iter()
                .map(|name| name.as_ref())
                .collect::<SmallVec<[&str; 8]>>();
            if !matches!(
                AccountCategories::new(&self.exchange).add_keywords(
                    &self.server.core.email.limits,
                    &names,
                    &mut keywords,
                    &mut spellings,
                ),
                CategoryOutcome::Changed | CategoryOutcome::Renamed | CategoryOutcome::Unchanged
            ) {
                return Ok(Err(SyncStatus::CONVERSION_ERROR));
            }
        }
        let owner = self
            .server
            .exchange_quota_owner(&self.ctx.access_token, self.ctx.account_id)
            .await?;
        let created = self
            .server
            .create_email(
                IngestEmail {
                    raw_message: &raw,
                    blob_hash: None,
                    message: MessageParser::new().parse(&raw).as_ref(),
                    access_token: &self.ctx.access_token,
                    mailbox_ids: vec![self.target.mailbox_id],
                    keywords,
                    received_at: None,
                    source: IngestSource::Jmap {
                        train_classifier: false,
                    },
                    metadata: None,
                    session_id: self.ctx.session.session_id,
                },
                owner,
                CreatedEmail {
                    spellings,
                    ..Default::default()
                },
                self.server.core.exchange.max_object_size,
            )
            .await;
        match created {
            Ok(email) => Ok(Ok(self.wrote(email.document_id, email.change_id))),
            Err(err) => write_status(err).map(Err),
        }
    }

    async fn change(
        &mut self,
        cache: &MessageStoreCache,
        server_id: &str,
        data: &RawApplicationData<'_>,
        view: &ClientView,
    ) -> Outcome<NoteTarget> {
        let Some(document_id) = self
            .target
            .document_id(cache, server_id)
            .filter(|document_id| view.shows(*document_id))
        else {
            return Ok(Err(SyncStatus::OBJECT_NOT_FOUND));
        };
        if !self.edited.insert(document_id) || self.deleted.contains(document_id) {
            return Ok(Err(SyncStatus::CONFLICT));
        }
        let Some(note) = self.parse(data) else {
            return Ok(Err(SyncStatus::CONVERSION_ERROR));
        };
        let unchanged = Ok(Ok(NoteTarget::Categories {
            document_id,
            replaced: false,
        }));
        let subject = note.subject.as_deref();
        let body = note.body.as_ref().and_then(note_body);
        if subject.is_none() && body.is_none() {
            return unchanged;
        }
        let Some((stored, _reservation)) =
            fetch_raw_message(self.server, self.ctx.account_id, document_id).await?
        else {
            return Ok(Err(SyncStatus::OBJECT_NOT_FOUND));
        };
        let parsed = MessageParser::new().parse(&stored);
        let current_subject = parsed
            .as_ref()
            .and_then(|message| message.subject())
            .unwrap_or_default();
        let current_body = parsed.as_ref().map(stored_body);
        let subject = subject.filter(|subject| *subject != current_subject);
        let body = body.filter(|body| {
            current_body
                .as_ref()
                .is_none_or(|current| !body.same_content(current))
        });
        if subject.is_none() && body.is_none() {
            return unchanged;
        }
        let body = body.or(current_body).unwrap_or_else(empty_body);
        let Some(raw) = compose(subject.unwrap_or(current_subject), &body) else {
            return Ok(Err(SyncStatus::CONVERSION_ERROR));
        };
        let Some(data) = cache.message_data(document_id) else {
            return Ok(Err(SyncStatus::OBJECT_NOT_FOUND));
        };
        let object = if self.exchange.has_object(Collection::Email, document_id) {
            self.server
                .exchange_object(self.ctx.account_id, Collection::Email, document_id)
                .await?
        } else {
            None
        };
        let carried = object
            .as_ref()
            .map(|object| object.deserialize::<ExchangeObject>())
            .transpose()?;
        let owner = self
            .server
            .exchange_quota_owner(&self.ctx.access_token, self.ctx.account_id)
            .await?;
        let replaced = self
            .server
            .replace_email(
                IngestEmail {
                    raw_message: &raw,
                    blob_hash: None,
                    message: MessageParser::new().parse(&raw).as_ref(),
                    access_token: &self.ctx.access_token,
                    mailbox_ids: Vec::new(),
                    keywords: Vec::new(),
                    received_at: None,
                    source: IngestSource::Jmap {
                        train_classifier: false,
                    },
                    metadata: None,
                    session_id: self.ctx.session.session_id,
                },
                self.ctx.access_token.changed_by(),
                owner,
                ReplacedEmail {
                    document_id,
                    data: &data,
                    identity: StoredPlacement {
                        container: self.target.mailbox_id,
                        item: self
                            .exchange
                            .email_item(self.target.mailbox_id, document_id),
                    },
                    alias: self
                        .exchange
                        .alias_of(document_id)
                        .map(StoredPlacement::from),
                    object: object.as_ref(),
                    added_keywords: 0,
                    removed_keywords: 0,
                    keywords_extra: None,
                },
                carried,
                self.server.core.exchange.max_object_size,
            )
            .await;
        match replaced {
            Ok(email) => Ok(Ok(NoteTarget::Categories {
                document_id: self.wrote(email.document_id, email.change_id),
                replaced: true,
            })),
            Err(err) => write_status(err).map(Err),
        }
    }

    fn parse<'d>(&self, data: &RawApplicationData<'d>) -> Option<Box<Note<'d>>> {
        match data.parse(Class::Notes, self.ctx.version, &WbxmlLimits::DEFAULT) {
            Ok(ApplicationData::Note(note))
                if note.message_class.as_deref().is_none_or(is_note_class) =>
            {
                Some(note)
            }
            _ => None,
        }
    }

    fn wrote(&mut self, document_id: u32, change_id: u64) -> u32 {
        self.result.change_id = self.result.change_id.max(Some(change_id));
        self.result.wrote = true;
        document_id
    }
}

fn is_note_class(class: &str) -> bool {
    class
        .split_at_checked(MESSAGE_CLASS_NOTE.len())
        .is_some_and(|(base, rest)| {
            base.eq_ignore_ascii_case(MESSAGE_CLASS_NOTE)
                && (rest.is_empty() || rest.starts_with('.'))
        })
}

fn empty_body<'x>() -> NoteBody<'x> {
    NoteBody {
        kind: TextKind::Plain,
        text: Cow::Borrowed(""),
    }
}

fn note_body<'x>(body: &'x Body<'_>) -> Option<NoteBody<'x>> {
    incoming_body(body).map(|(kind, text)| NoteBody {
        kind,
        text: Cow::Borrowed(text),
    })
}

fn stored_body<'x>(message: &'x Message<'_>) -> NoteBody<'x> {
    let html = message
        .html_body()
        .next()
        .is_some_and(|part| matches!(part.kind(), PartKind::Html));
    if html {
        NoteBody {
            kind: TextKind::Html,
            text: message.body_html(0).unwrap_or_default(),
        }
    } else {
        NoteBody {
            kind: TextKind::Plain,
            text: message.body_text(0).unwrap_or_default(),
        }
    }
}

fn compose(subject: &str, body: &NoteBody<'_>) -> Option<Vec<u8>> {
    let builder = MessageBuilder::new().subject(subject);
    match body.kind {
        TextKind::Plain => builder.text_body(body.text.as_ref()),
        TextKind::Html => builder.html_body(body.text.as_ref()),
    }
    .write_to_vec()
    .ok()
}

fn write_status(err: trc::Error) -> trc::Result<SyncStatus> {
    match err.as_ref() {
        EventType::Limit(LimitEvent::SizeRequest)
        | EventType::MessageIngest(MessageIngestEvent::Error) => Ok(SyncStatus::CONVERSION_ERROR),
        _ => store_status(err).map_err(|err| err.caused_by(trc::location!())),
    }
}
