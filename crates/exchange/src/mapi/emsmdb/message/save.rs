/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{
    BODY_SOURCES, FLAG_STATUS_FLAGGED,
    attach_row::push_attachment_properties,
    fai::holds_normal_fai_rows,
    import::ImportSave,
    load::{MAX_DECODED, convert_error},
    object_row::{
        carried_properties, carry_message_class, carry_resend, category_names, encode_key,
        encode_property, flag_status_key, is_carried, is_carried_value, is_category,
        is_flag_complete, resend_key, set_resend,
    },
    write::drop_unsaved_attachments,
};
use crate::{
    cache::ExchangeCacheFetch,
    eas::{convert::flag::LastVerb, folder_sync::MAX_STATE_ATTEMPTS},
    folders::{FolderNode, SpecialFolder},
    groupware_write::new_event,
    identity::org_dn,
    mail::{AccountCategories, CategoryOutcome, CommitOutcome, FlagEdit, FlagOutcome, MailEdits},
    mapi::{
        emsmdb::{
            access::ItemWrite,
            execute::{RopContext, RopError, RopResult},
            resolve::DirectoryResolver,
            staged::{EmbeddedDiscard, RowBaseline, Touched, TouchedFlags},
            state::MessageObject,
            store::StoreGuids,
        },
        ids::{ChangeSpace, IdSpace, MapiId},
    },
    store::{
        FolderKind, FolderRef,
        account::ExchangeAccountStore,
        category::SpellingChanges,
        object::{
            CreatedEmail, ExchangeObject, ExchangeObjectStore, ExchangeObjectWrite, ObjectVersion,
            OwnerStamp, ReplacedEmail, StoredPlacement,
        },
    },
};
use calcard::icalendar::ICalendarMethod;
use email::{
    cache::email::MessageCacheAccess,
    mailbox::JUNK_ID,
    message::ingest::{IngestEmail, IngestSource},
};
use exchange_proto::{
    convert::{
        RECEIVED_REPRESENTING_IDS,
        context::{BodyPreference, ConvertOptions, StoreIds, TnefPolicy},
        ical::{MeetingMessage, invited_address, meeting_to_itip, meeting_uid},
        mime::{CalendarPart, derive_envelope_props, message_to_mime},
        model::{MessageContent, PropBag as ContentBag},
        tags::message_flags,
    },
    ids::Eid,
    mapi::{
        ErrorCode,
        prop::{OwnedPropValue, PropId, PropKeyRef, PropType, tags},
        rop::{DecodedRop, requests::SaveChangesMessage, responses::SaveChangesMessageResponse},
    },
};
use groupware::{cache::GroupwareCache, calendar::CalendarEventContent};
use jiff::Timestamp;
use mail_parser::{Message, MessageParser};
use smallvec::SmallVec;
use std::{borrow::Cow, str, sync::Arc};
use store::write::{BatchBuilder, PendingId};
use trc::{AddContext, EventType, LimitEvent};
use types::{
    collection::{Collection, SyncCollection},
    field::CalendarEventField,
    keyword::{ANSWERED, DRAFT, FLAGGED, FORWARDED, Keyword, SEEN},
    type_state::DataType,
};

const FORCE_SAVE: u8 = 0x04;
const VERB_KEY: PropKeyRef<'static> = PropKeyRef::Tag(tags::LAST_VERB_EXECUTED.id());
const REFERENCES_KEY: PropKeyRef<'static> = PropKeyRef::Tag(tags::INTERNET_REFERENCES.id());

pub(super) fn meeting_message(content: &MessageContent) -> Option<MeetingMessage> {
    match content
        .props
        .get_any(PropKeyRef::Tag(tags::MESSAGE_CLASS.id()))?
    {
        OwnedPropValue::Unicode(class) => MeetingMessage::of_class(class),
        OwnedPropValue::String8(class) => MeetingMessage::of_class(str::from_utf8(class).ok()?),
        _ => None,
    }
}

pub(super) struct Saved {
    pub folder: MapiId,
    pub id: MapiId,
    pub origin: Option<u64>,
    pub row: RowBaseline,
    pub change: Option<u64>,
}

pub(in crate::mapi::emsmdb) struct Created {
    pub id: MapiId,
    pub origin: Option<u64>,
    pub change: u64,
    pub respelled: bool,
    pub row: RowBaseline,
}

#[derive(Debug, Clone, Copy)]
pub struct MailContainer {
    pub mailbox_id: u32,
    pub container: u32,
    pub store_instance: u64,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum SaveMode {
    Checked,
    Force,
}

#[derive(Clone, Copy)]
pub struct SaveTarget {
    pub base: Option<MapiId>,
    pub origin: Option<u64>,
    pub row: RowBaseline,
    pub mode: SaveMode,
}

#[derive(Clone, Copy)]
enum MimeBuild {
    Full,
    Envelope,
}

#[derive(Default, Clone, Copy)]
pub(super) struct MailFlags {
    read: Option<bool>,
    draft: Option<bool>,
    flagged: Option<bool>,
    answered: Option<bool>,
    forwarded: Option<bool>,
}

impl MailFlags {
    pub(super) fn from_props(props: &ContentBag, touched: TouchedFlags) -> Self {
        let mut flags = MailFlags::default();
        if touched.contains(tags::MESSAGE_FLAGS)
            && let Some(OwnedPropValue::I32(value)) =
                props.get(PropKeyRef::Tag(tags::MESSAGE_FLAGS.id()), PropType::I32)
        {
            flags.read = Some(value & message_flags::READ != 0);
            flags.draft = Some(value & message_flags::UNSENT != 0);
        }
        if touched.contains(tags::READ)
            && let Some(OwnedPropValue::Bool(read)) =
                props.get(PropKeyRef::Tag(tags::READ.id()), PropType::Bool)
        {
            flags.read = Some(*read);
        }
        if touched.contains(tags::FLAG_STATUS) {
            flags.flagged = Some(matches!(
                props.get(PropKeyRef::Tag(tags::FLAG_STATUS.id()), PropType::I32),
                Some(OwnedPropValue::I32(FLAG_STATUS_FLAGGED))
            ));
        }
        flags
    }

    pub(super) fn with_verb(mut self, props: &ContentBag) -> Self {
        if let Some(OwnedPropValue::I32(verb)) = props.get(VERB_KEY, PropType::I32) {
            match LastVerb::from_mapi(*verb) {
                Some(LastVerb::ReplyToSender | LastVerb::ReplyToAll) => self.answered = Some(true),
                Some(LastVerb::Forward) => self.forwarded = Some(true),
                None => {}
            }
        }
        self
    }

    fn keywords(self) -> Vec<Keyword> {
        let mut keywords = Vec::with_capacity(5);
        if self.read.unwrap_or(true) {
            keywords.push(Keyword::Seen);
        }
        if self.draft.unwrap_or(true) {
            keywords.push(Keyword::Draft);
        }
        for (value, keyword) in [
            (self.flagged, Keyword::Flagged),
            (self.answered, Keyword::Answered),
            (self.forwarded, Keyword::Forwarded),
        ] {
            if value == Some(true) {
                keywords.push(keyword);
            }
        }
        keywords
    }

    fn keyword_bits(self, current: u32) -> (u32, u32) {
        let mut added = 0;
        let mut removed = 0;
        for (value, bit) in [
            (self.read, 1u32 << SEEN),
            (self.flagged, 1u32 << FLAGGED),
            (self.answered, 1u32 << ANSWERED),
            (self.forwarded, 1u32 << FORWARDED),
        ] {
            match value {
                Some(true) if current & bit == 0 => added |= bit,
                Some(false) if current & bit != 0 => removed |= bit,
                _ => {}
            }
        }
        (added, removed)
    }

    pub(super) fn edit(self) -> FlagEdit {
        FlagEdit {
            read: self.read,
            flagged: self.flagged,
            answered: self.answered,
            forwarded: self.forwarded,
            ..Default::default()
        }
    }
}

enum Resave {
    Flags,
    Object,
    Replace,
}

impl RopContext<'_, '_> {
    pub async fn save_changes_message(
        &mut self,
        rop: &DecodedRop<'_>,
        index: u8,
        request: &SaveChangesMessage,
    ) -> RopResult {
        let handle = self.input(rop.header.input_handle)?;
        let message = self.message_object(handle)?;
        let input_handle_index = rop.header.input_handle;
        if !message.path.is_empty() {
            return self.save_embedded(rop, index, &message, input_handle_index);
        }
        let Some(staged_id) = message.staged else {
            let saved = message
                .id()
                .filter(|_| message.path.is_empty())
                .ok_or(ErrorCode::NOT_SUPPORTED)?;
            return self.respond(
                rop,
                index,
                &SaveChangesMessageResponse {
                    input_handle_index,
                    message_id: saved.to_client_message().to_eid(),
                },
            );
        };
        let mode = if request.save_flags & FORCE_SAVE != 0 {
            SaveMode::Force
        } else {
            SaveMode::Checked
        };
        let saved = self.commit_staged(&message, staged_id, mode).await?;
        self.respond(
            rop,
            index,
            &SaveChangesMessageResponse {
                input_handle_index,
                message_id: saved.id.to_client_message().to_eid(),
            },
        )
    }

    fn save_embedded(
        &mut self,
        rop: &DecodedRop<'_>,
        index: u8,
        message: &MessageObject,
        input_handle_index: u8,
    ) -> RopResult {
        if message.staged.is_some() {
            let staged = self.staged_message(message)?;
            staged.content_at(&message.path)?;
            staged.unsaved_embedded.saved(&message.path);
        }
        self.respond(
            rop,
            index,
            &SaveChangesMessageResponse {
                input_handle_index,
                message_id: Eid::from_le_u64(0),
            },
        )
    }

    pub(super) async fn commit_staged(
        &mut self,
        message: &MessageObject,
        staged_id: u32,
        mode: SaveMode,
    ) -> Result<Saved, RopError> {
        if !message.path.is_empty() {
            return Err(RopError::Code(ErrorCode::NOT_SUPPORTED));
        }
        let staged = self.staged_message(message)?;
        if let Some(failure) = staged.failed.first() {
            return Err(RopError::Code(failure.code));
        }
        let (associated, existing) = (staged.associated, staged.base.is_some());
        let folder = MapiId::from_counter(message.folder).ok_or(ErrorCode::NOT_FOUND)?;
        let fai = associated
            || match folder.to_node() {
                Some(node) => self
                    .folder_tree(message.mailbox_id)
                    .await?
                    .get(node)
                    .is_some_and(holds_normal_fai_rows),
                None => false,
            };
        self.require_write(
            message.mailbox_id,
            message.folder,
            ItemWrite::of_staged(fai, existing),
        )
        .await?;
        self.staged()
            .discard_embedded(staged_id, EmbeddedDiscard::Committed)?;
        let staged = self.staged_message(message)?;
        drop_unsaved_attachments(staged);
        let target = SaveTarget {
            base: staged.base,
            origin: staged.origin,
            row: staged.row,
            mode,
        };
        let import = staged.import.as_deref().map(|import| {
            (
                import.collector,
                import.resolution,
                ImportSave {
                    version: import.version.clone(),
                    item: import.item,
                    stored_change: import.stored_change,
                },
            )
        });
        let stored_change = import
            .as_ref()
            .and_then(|(_, _, import)| import.stored_change);
        let saved = if fai {
            let (id, origin) = self
                .save_fai(
                    message,
                    target,
                    import.as_ref().map(|(_, _, import)| import),
                )
                .await?;
            if let Some((collector, resolution, _)) = import {
                let replica = self.store_guids(message.mailbox_id).await?.replica;
                let (change, given) = resolution.recorded(origin, id);
                self.record_fai_import_change(collector, change, given, replica)?;
            }
            Saved {
                folder,
                id,
                origin,
                row: RowBaseline::Untracked,
                change: None,
            }
        } else if let Some((collector, resolution, import)) = import {
            let (saved, space) = match self
                .groupware_folder(message.mailbox_id, message.folder)
                .await?
            {
                Some(folder) => (
                    self.save_groupware_import(message, folder, target, (collector, import))
                        .await?,
                    folder.change_space(),
                ),
                None if self.types.contains(DataType::Email) => (
                    self.save_import(message, target, import).await?,
                    ChangeSpace::Email,
                ),
                None => return Err(RopError::Code(ErrorCode::ACCESS_DENIED)),
            };
            let replica = self.store_guids(message.mailbox_id).await?.replica;
            let (change, given) = resolution.recorded(saved.change, saved.id);
            self.record_import_change(collector, change, given, (replica, space))?;
            saved
        } else if let Some(folder) = self
            .groupware_folder(message.mailbox_id, message.folder)
            .await?
        {
            let saved = self.save_groupware(message, folder, target, None).await?;
            match target.base.filter(|base| base.space == IdSpace::Email) {
                Some(client) => Saved {
                    id: client,
                    ..saved
                },
                None => saved,
            }
        } else {
            self.save_email(message, target).await?
        };
        if let Some(staged) = self.staged().message(staged_id) {
            staged.saved(saved.id);
            staged.origin = saved.origin;
            staged.change = saved.change.or(stored_change);
            staged.row = saved.row;
        }
        self.state
            .assign_saved(staged_id, saved.folder.counter(), saved.id.counter());
        self.invalidate_mailbox();
        Ok(saved)
    }

    async fn save_email(
        &mut self,
        message: &MessageObject,
        target: SaveTarget,
    ) -> Result<Saved, RopError> {
        if !self.types.contains(DataType::Email) {
            return Err(RopError::Code(ErrorCode::ACCESS_DENIED));
        }
        let container = match MapiId::from_counter(message.folder).and_then(MapiId::to_node) {
            Some(FolderNode::Stored(FolderRef {
                kind: FolderKind::Mailbox,
                id,
            })) => id,
            Some(FolderNode::Special(SpecialFolder::Outbox)) => {
                match self
                    .folder_tree(message.mailbox_id)
                    .await?
                    .special(SpecialFolder::Drafts)
                    .map(|entry| entry.node)
                {
                    Some(FolderNode::Stored(FolderRef {
                        kind: FolderKind::Mailbox,
                        id,
                    })) => id,
                    _ => return Err(RopError::Code(ErrorCode::NOT_SUPPORTED)),
                }
            }
            _ => return Err(RopError::Code(ErrorCode::NOT_SUPPORTED)),
        };
        let folder = MapiId::new(IdSpace::Mailbox, container);
        match target.base {
            None => self
                .create_mail(message, container, ObjectVersion::Server, None)
                .await
                .map(|created| (created.id, created.origin, created.row)),
            Some(base) => self.resave_mail(message, container, base, target).await,
        }
        .map(|(id, origin, row)| Saved {
            folder,
            id,
            origin,
            row,
            change: None,
        })
    }

    async fn staged_mime(
        &mut self,
        message: &MessageObject,
        build: MimeBuild,
    ) -> Result<Vec<u8>, RopError> {
        let staged = self.staged_message(message)?.content.clone();
        let content = match build {
            MimeBuild::Full => Cow::Borrowed(staged.as_ref()),
            MimeBuild::Envelope => Cow::Owned(MessageContent {
                props: filtered_props(&staged.props, |key| !is_category(key) && !is_body(key)),
                recipients: staged.recipients.clone(),
                attachments: Vec::new(),
            }),
        };
        let store_instance = self
            .mailbox(message.mailbox_id)
            .await?
            .exchange
            .store_instance;
        self.content_mime(
            &content,
            message.mailbox_id,
            StoreGuids::new(store_instance, message.mailbox_id),
            build,
        )
        .await
    }

    async fn content_mime(
        &mut self,
        content: &MessageContent,
        mailbox_id: u32,
        guids: StoreGuids,
        build: MimeBuild,
    ) -> Result<Vec<u8>, RopError> {
        let server = self.request.server;
        let resolver =
            DirectoryResolver::for_content(server, self.request.access_token, content).await?;
        let org = org_dn().ok_or(ErrorCode::ERROR)?;
        let opts = ConvertOptions {
            org_dn: &org,
            store: Some(StoreIds {
                store_guid: guids.mailbox,
                replguid: guids.replica,
            }),
            body_preference: BodyPreference::Html,
            tnef: TnefPolicy::Decode,
            max_decoded: MAX_DECODED,
        };
        let itip = match (build, meeting_message(content)) {
            (MimeBuild::Full, Some(message)) => {
                self.meeting_itip(content, mailbox_id, message, &resolver)
                    .await?
            }
            _ => None,
        };
        let calendar = itip
            .as_ref()
            .map(|(method, text)| CalendarPart { method, text });
        let mut raw = Vec::new();
        message_to_mime(content, &resolver, &opts, calendar, &mut raw)
            .map_err(|err| RopError::Code(convert_error(err)))?;
        if raw.len() > server.core.email.mail_max_size {
            return Err(RopError::Code(ErrorCode::TOO_BIG));
        }
        Ok(raw)
    }

    async fn meeting_itip(
        &mut self,
        content: &MessageContent,
        account_id: u32,
        message: MeetingMessage,
        resolver: &DirectoryResolver,
    ) -> Result<Option<(ICalendarMethod, String)>, RopError> {
        let Some(uid) = meeting_uid(&content.props) else {
            return Ok(None);
        };
        let server = self.request.server;
        let account_info = server
            .account_info(account_id)
            .await
            .caused_by(trc::location!())?;
        let addresses = account_info.addresses();
        let sender = match message {
            MeetingMessage::Accepted | MeetingMessage::Tentative | MeetingMessage::Declined => {
                self.invited_address(account_id, &uid, addresses).await?
            }
            MeetingMessage::Request | MeetingMessage::Cancel => None,
        };
        let Some(sender) = sender.or_else(|| addresses.first().map(String::as_str)) else {
            return Ok(None);
        };
        let mut ical = new_event(&uid, Timestamp::now());
        match meeting_to_itip(&mut ical, message, content, sender, resolver) {
            Ok(()) => Ok(Some((message.method(), ical.to_string()))),
            Err(err) => {
                trc::event!(
                    Calendar(trc::CalendarEvent::ItipMessageError),
                    AccountId = account_id,
                    Details = "MAPI meeting message sent without iMIP",
                    Reason = format!("{message:?}: {err:?}"),
                );
                Ok(None)
            }
        }
    }

    async fn invited_address<'a>(
        &self,
        account_id: u32,
        uid: &str,
        addresses: &'a [String],
    ) -> trc::Result<Option<&'a str>> {
        if addresses.len() < 2 || !self.types.contains(DataType::CalendarEvent) {
            return Ok(None);
        }
        let server = self.request.server;
        let Some(document_id) = server
            .fetch_groupware_resources(account_id, account_id, SyncCollection::Calendar)
            .await
            .caused_by(trc::location!())?
            .uid_matches(uid)
            .min()
        else {
            return Ok(None);
        };
        let (_, Some(content)) = server
            .archive_and_field(
                account_id,
                Collection::CalendarEvent,
                document_id,
                CalendarEventField::Content.into(),
            )
            .await
            .caused_by(trc::location!())?
        else {
            return Ok(None);
        };
        let ical = content
            .deserialize::<CalendarEventContent>()
            .caused_by(trc::location!())?
            .data
            .event;
        Ok(invited_address(&ical, addresses))
    }

    pub(super) async fn create_mail(
        &mut self,
        message: &MessageObject,
        container: u32,
        version: ObjectVersion,
        alias: Option<u32>,
    ) -> Result<Created, RopError> {
        let content = self.staged_message(message)?.content.clone();
        let exchange = self.mailbox(message.mailbox_id).await?.exchange;
        self.create_mail_content(
            &content,
            MailContainer {
                mailbox_id: message.mailbox_id,
                container,
                store_instance: exchange.store_instance,
            },
            AccountCategories::new(&exchange),
            version,
            alias,
        )
        .await
    }

    pub(in crate::mapi::emsmdb) async fn create_mail_content(
        &mut self,
        content: &MessageContent,
        target: MailContainer,
        categories: AccountCategories<'_>,
        version: ObjectVersion,
        alias: Option<u32>,
    ) -> Result<Created, RopError> {
        let raw = self
            .content_mime(
                content,
                target.mailbox_id,
                StoreGuids::new(target.store_instance, target.mailbox_id),
                MimeBuild::Full,
            )
            .await?;
        let parsed = MessageParser::new().parse(&raw);
        let server = self.request.server;
        let carried = carried_object(
            target.mailbox_id,
            content,
            &envelope_props(parsed.as_ref()),
            server.core.exchange.max_object_size,
            |_| true,
        );
        let mut keywords = MailFlags::from_props(&content.props, TouchedFlags::ALL)
            .with_verb(&content.props)
            .keywords();
        let mut spellings = SpellingChanges::default();
        if let Some(names) = category_names(&content.props) {
            let names = names
                .iter()
                .map(AsRef::as_ref)
                .collect::<SmallVec<[&str; 8]>>();
            match categories.add_keywords(
                &server.core.email.limits,
                &names,
                &mut keywords,
                &mut spellings,
            ) {
                CategoryOutcome::Changed
                | CategoryOutcome::Renamed
                | CategoryOutcome::Unchanged => {}
                CategoryOutcome::KeywordLimit | CategoryOutcome::InvalidName => {
                    return Err(RopError::Code(ErrorCode::ERROR));
                }
            }
        }
        let respelled = !spellings.is_empty();
        let access_token = self.request.access_token;
        let owner = server
            .exchange_quota_owner(access_token, target.mailbox_id)
            .await?;
        let mailbox_token = server
            .exchange_target_token(access_token, target.mailbox_id)
            .await?;
        let (email, row) = server
            .create_email_tracked(
                IngestEmail {
                    raw_message: &raw,
                    blob_hash: None,
                    message: parsed.as_ref(),
                    access_token: mailbox_token.as_ref().unwrap_or(access_token),
                    mailbox_ids: vec![target.container],
                    keywords,
                    received_at: None,
                    source: IngestSource::Jmap {
                        train_classifier: target.container == JUNK_ID,
                    },
                    metadata: None,
                    session_id: self.session_id(),
                },
                owner,
                CreatedEmail {
                    carried: Some(carried),
                    version,
                    alias,
                    spellings,
                },
                server.core.exchange.max_object_size,
            )
            .await
            .map_err(write_error)?;
        Ok(Created {
            id: MapiId::new(IdSpace::Email, alias.unwrap_or(email.document_id)),
            origin: Some(u64::from(email.document_id)),
            change: email.change_id,
            respelled,
            row,
        })
    }

    pub(super) async fn stored_content(
        &mut self,
        message: &MessageObject,
    ) -> Result<Arc<MessageContent>, RopError> {
        let stored = MessageObject {
            staged: None,
            ..message.clone()
        };
        self.message_root(&stored).await
    }

    async fn envelope_derived(&mut self, message: &MessageObject) -> Result<ContentBag, RopError> {
        let raw = self.staged_mime(message, MimeBuild::Envelope).await?;
        let mut derived = ContentBag::new();
        if let Some(parsed) = MessageParser::new().parse_headers(&raw) {
            derive_envelope_props(&parsed, None, &mut derived);
        }
        Ok(derived)
    }

    pub(super) async fn resave_mail(
        &mut self,
        message: &MessageObject,
        container: u32,
        base: MapiId,
        target: SaveTarget,
    ) -> Result<(MapiId, Option<u64>, RowBaseline), RopError> {
        let staged = self.staged_message(message)?;
        let verb_touched = match &staged.touched {
            Touched::Keys(keys) => keys.iter().any(|key| key.as_ref() == VERB_KEY),
            Touched::Structure => staged.content.props.get_any(VERB_KEY).is_some(),
        };
        let mut flags = (!staged.flags_touched.is_empty() || verb_touched).then(|| {
            let flags = MailFlags::from_props(&staged.content.props, staged.flags_touched);
            if verb_touched {
                flags.with_verb(&staged.content.props)
            } else {
                flags
            }
        });
        let status_touched = staged.flags_touched.contains(tags::FLAG_STATUS);
        let content = staged.content.clone();
        let categories_touched = staged.categories_touched;
        let representing = staged.representing_touched;
        let mut keys = match &staged.touched {
            Touched::Keys(keys) if keys.is_empty() && flags.is_none() && !categories_touched => {
                return Ok((base, target.origin, target.row));
            }
            Touched::Keys(keys) => Some(keys.clone()),
            Touched::Structure => None,
        };
        let categories = if categories_touched {
            let view = self.mailbox(message.mailbox_id).await?;
            let document_id = view.email_document(container, base.id);
            let current = view
                .messages
                .as_ref()
                .and_then(|messages| {
                    messages
                        .email_by_id(&document_id)
                        .map(|item| messages.custom_keywords(item))
                })
                .unwrap_or_default();
            category_target(
                category_names(&content.props),
                AccountCategories::new(&view.exchange).resolve(current),
            )
        } else {
            None
        };
        let stored = self.stored_content(message).await?;
        if let Some(keys) = &mut keys {
            if status_touched && is_flag_complete(&content.props) != is_flag_complete(&stored.props)
            {
                keys.push(flag_status_key());
            }
            keys.retain(|key| {
                content.props.get_any(key.as_ref()) != stored.props.get_any(key.as_ref())
            });
            if keys.is_empty() && flags.is_none() && categories.is_none() {
                return Ok((base, target.origin, target.row));
            }
        }
        let withheld = RECEIVED_REPRESENTING_IDS
            .into_iter()
            .filter(|&id| {
                let value = content.props.get_any(PropKeyRef::Tag(id));
                !representing.contains(id)
                    || (value.is_some() && value == stored.props.get_any(PropKeyRef::Tag(id)))
            })
            .collect::<SmallVec<[PropId; 6]>>();
        drop(stored);
        let server = self.request.server;
        let access_token = self.request.access_token;
        let account_id = message.mailbox_id;
        let owner = server
            .exchange_quota_owner(access_token, account_id)
            .await?;
        let mailbox_token = server
            .exchange_target_token(access_token, account_id)
            .await?;
        let max_size = server.core.exchange.max_object_size;
        let mut envelope: Option<ContentBag> = None;
        let mut mime: Option<Vec<u8>> = None;
        let mut origin = target.origin;
        let mut row = target.row;
        for _ in 0..MAX_STATE_ATTEMPTS {
            let view = self.mailbox(account_id).await?;
            let mut document_id = view.email_document(container, base.id);
            let mut data = view
                .messages
                .as_ref()
                .filter(|messages| {
                    messages
                        .email_by_id(&document_id)
                        .is_some_and(|item| item.has_mailbox_id(container))
                })
                .and_then(|messages| messages.message_data(document_id))
                .ok_or(ErrorCode::OBJECT_DELETED)?;
            if target.mode == SaveMode::Checked
                && origin.is_some_and(|origin| origin != u64::from(document_id))
            {
                return Err(RopError::Code(ErrorCode::OBJECT_MODIFIED));
            }
            let draft = data.keywords & (1 << DRAFT) != 0;
            let object = if view.exchange.has_object(Collection::Email, document_id) {
                server
                    .exchange_object(account_id, Collection::Email, document_id)
                    .await
                    .caused_by(trc::location!())?
            } else {
                None
            };
            let current = match &object {
                Some(object) => Some(object.deserialize::<ExchangeObject>()?),
                None => None,
            };
            let in_row = |key: PropKeyRef<'_>| {
                current
                    .as_ref()
                    .is_some_and(|object| object.property(&encode_key(key)).is_some())
            };
            let plan = match &keys {
                None => Resave::Replace,
                Some(keys) if keys.is_empty() => Resave::Flags,
                Some(keys)
                    if keys.iter().all(|key| {
                        let key = key.as_ref();
                        in_row(key) && key != REFERENCES_KEY
                    }) =>
                {
                    Resave::Object
                }
                Some(keys) => {
                    let derived = match &mut envelope {
                        Some(derived) => derived,
                        empty => empty.insert(self.envelope_derived(message).await?),
                    };
                    if keys.iter().any(|key| {
                        let key = key.as_ref();
                        !is_carried(key)
                            || derived.get_any(key).is_some()
                            || (key == REFERENCES_KEY && in_row(key))
                            || (content.props.get_any(key).is_none() && !in_row(key))
                    }) {
                        Resave::Replace
                    } else {
                        Resave::Object
                    }
                }
            };
            if let (Some(names), Resave::Replace | Resave::Object) = (&categories, &plan)
                && let CategoryOutcome::KeywordLimit | CategoryOutcome::InvalidName =
                    MailEdits::new(account_id).set_categories(
                        &server.core.email.limits,
                        document_id,
                        &data,
                        flags.map(MailFlags::edit).unwrap_or_default(),
                        names,
                        AccountCategories::new(&view.exchange),
                    )?
            {
                return Err(RopError::Code(ErrorCode::ERROR));
            }
            match plan {
                Resave::Replace if !draft => {
                    return Err(RopError::Code(ErrorCode::NOT_SUPPORTED));
                }
                Resave::Replace
                    if target.mode == SaveMode::Checked
                        && !row.is_current(object.as_ref().map(|object| &object.version)) =>
                {
                    return Err(RopError::Code(ErrorCode::OBJECT_MODIFIED));
                }
                Resave::Replace => {
                    let raw = match &mut mime {
                        Some(raw) => raw,
                        empty => empty.insert(self.staged_mime(message, MimeBuild::Full).await?),
                    };
                    let parsed = MessageParser::new().parse(raw.as_slice());
                    let mut carried = carried_object(
                        account_id,
                        &content,
                        &envelope_props(parsed.as_ref()),
                        max_size,
                        |key| {
                            in_row(key)
                                || !matches!(key, PropKeyRef::Tag(id) if withheld.contains(&id))
                        },
                    );
                    set_resend(&mut carried, in_row(resend_key()));
                    let (added_keywords, removed_keywords) =
                        flags.map_or((0, 0), |flags| flags.keyword_bits(data.keywords));
                    let identity = StoredPlacement {
                        container,
                        item: view.email_item(container, document_id),
                    };
                    match server
                        .replace_email_tracked(
                            IngestEmail {
                                raw_message: raw,
                                blob_hash: None,
                                message: parsed.as_ref(),
                                access_token: mailbox_token.as_ref().unwrap_or(access_token),
                                mailbox_ids: Vec::new(),
                                keywords: Vec::new(),
                                received_at: None,
                                source: IngestSource::Jmap {
                                    train_classifier: false,
                                },
                                metadata: None,
                                session_id: self.session_id(),
                            },
                            access_token.changed_by(),
                            owner,
                            ReplacedEmail {
                                document_id,
                                data: &data,
                                identity,
                                alias: view
                                    .exchange
                                    .alias_of(document_id)
                                    .map(StoredPlacement::from),
                                object: object.as_ref(),
                                added_keywords,
                                removed_keywords,
                                keywords_extra: None,
                            },
                            Some(carried),
                            max_size,
                        )
                        .await
                    {
                        Ok((email, written)) if categories.is_none() => {
                            return Ok((
                                MapiId::new(IdSpace::Email, identity.item),
                                Some(u64::from(email.document_id)),
                                written,
                            ));
                        }
                        Ok((email, written)) => {
                            row = written;
                            keys = Some(SmallVec::new());
                            flags = None;
                            document_id = email.document_id;
                            origin = Some(u64::from(document_id));
                            self.invalidate_mailbox();
                            data = self
                                .mailbox(account_id)
                                .await?
                                .messages
                                .as_ref()
                                .and_then(|messages| messages.message_data(document_id))
                                .ok_or(ErrorCode::OBJECT_DELETED)?;
                        }
                        Err(err) if err.is_assertion_failure() => {
                            self.invalidate_mailbox();
                            continue;
                        }
                        Err(err) => return Err(write_error(err)),
                    }
                }
                Resave::Object => {
                    let mut next = current.unwrap_or_default();
                    for key in keys.iter().flatten() {
                        let key = key.as_ref();
                        match content
                            .props
                            .get_any(key)
                            .filter(|value| is_carried_value(key, value))
                        {
                            Some(value) => {
                                let property = encode_property(key, value);
                                next.set_property(property.key, property.value);
                            }
                            None => {
                                next.remove_property(&encode_key(key));
                            }
                        }
                    }
                    let was_current = row.is_current(object.as_ref().map(|object| &object.version));
                    let mut batch = BatchBuilder::new();
                    let written = ExchangeObjectWrite {
                        owner,
                        collection: Collection::Email,
                        document_id: PendingId::Assigned(document_id),
                        stamp: OwnerStamp::Email {
                            thread_id: data.thread_id,
                        },
                        version: ObjectVersion::Server,
                        previous: object.as_ref(),
                        next: Some(next),
                        max_size,
                    }
                    .build_tracked(&mut batch)
                    .map_err(write_error)?;
                    match server.commit_batch(batch).await {
                        Ok(_) => {
                            server.mark_exchange_stale(account_id);
                            if was_current {
                                row = written;
                            }
                            keys = Some(SmallVec::new());
                            if flags.is_some() || categories.is_some() {
                                self.invalidate_mailbox();
                                data = self
                                    .mailbox(account_id)
                                    .await?
                                    .messages
                                    .as_ref()
                                    .and_then(|messages| messages.message_data(document_id))
                                    .ok_or(ErrorCode::OBJECT_DELETED)?;
                            }
                        }
                        Err(err) if err.is_assertion_failure() => {
                            self.invalidate_mailbox();
                            continue;
                        }
                        Err(err) => return Err(write_error(err)),
                    }
                }
                Resave::Flags => {}
            }
            let origin = Some(u64::from(document_id));
            let edit = flags.map(MailFlags::edit);
            let limits = &server.core.email.limits;
            let mut edits = MailEdits::new(account_id);
            match (&categories, edit) {
                (Some(names), edit) => {
                    let view = self.mailbox(account_id).await?;
                    match edits.set_categories(
                        limits,
                        document_id,
                        &data,
                        edit.unwrap_or_default(),
                        names,
                        AccountCategories::new(&view.exchange),
                    )? {
                        CategoryOutcome::Changed | CategoryOutcome::Renamed => {}
                        CategoryOutcome::Unchanged => return Ok((base, origin, row)),
                        CategoryOutcome::KeywordLimit | CategoryOutcome::InvalidName => {
                            return Err(RopError::Code(ErrorCode::ERROR));
                        }
                    }
                }
                (None, Some(edit)) => {
                    if let FlagOutcome::KeywordLimit =
                        edits.set_flags(limits, document_id, &data, edit)?
                    {
                        return Err(RopError::Code(ErrorCode::ERROR));
                    }
                }
                (None, None) => return Ok((base, origin, row)),
            }
            match edits
                .commit(server, access_token, self.session_id())
                .await?
            {
                CommitOutcome::Committed(_) => return Ok((base, origin, row)),
                CommitOutcome::Conflict => self.invalidate_mailbox(),
            }
        }
        Err(RopError::Code(ErrorCode::OBJECT_MODIFIED))
    }

    pub(in crate::mapi::emsmdb) fn session_id(&self) -> u64 {
        u64::try_from(self.session & u128::from(u64::MAX)).unwrap_or_default()
    }
}

pub(super) fn category_target<'x, 'k>(
    names: Option<&'x [Box<str>]>,
    current: impl IntoIterator<Item = Cow<'k, str>>,
) -> Option<SmallVec<[&'x str; 8]>> {
    let names = names
        .into_iter()
        .flatten()
        .map(AsRef::as_ref)
        .collect::<SmallVec<[&str; 8]>>();
    let mut current = current.into_iter();
    let unchanged = names
        .iter()
        .all(|name| current.next().is_some_and(|current| current == *name))
        && current.next().is_none();
    (!unchanged).then_some(names)
}

fn is_body(key: PropKeyRef<'_>) -> bool {
    matches!(key, PropKeyRef::Tag(id) if id == tags::HTML.id() || BODY_SOURCES.contains(&id))
}

fn filtered_props(props: &ContentBag, keep: impl Fn(PropKeyRef<'_>) -> bool) -> ContentBag {
    let mut out = ContentBag::new();
    for (key, value) in props.iter().filter(|(key, _)| keep(key.as_ref())) {
        out.set(key.clone(), value.clone());
    }
    out
}

fn envelope_props(parsed: Option<&Message<'_>>) -> ContentBag {
    let mut derived = ContentBag::new();
    if let Some(parsed) = parsed {
        derive_envelope_props(parsed, None, &mut derived);
    }
    derived
}

fn carried_object(
    account_id: u32,
    content: &MessageContent,
    derived: &ContentBag,
    max_size: usize,
    keep: impl Fn(PropKeyRef<'_>) -> bool,
) -> ExchangeObject {
    let mut properties = carried_properties(&content.props, |key| {
        keep(key)
            && match key {
                PropKeyRef::Tag(id)
                    if id == tags::SUBJECT_PREFIX.id()
                        || id == tags::NORMALIZED_SUBJECT.id()
                        || id == tags::INTERNET_REFERENCES.id() =>
                {
                    derived.get_any(key) != content.props.get_any(key)
                }
                _ => derived.get_any(key).is_none(),
            }
    });
    carry_message_class(
        &mut properties,
        &content.props,
        derived.text(tags::MESSAGE_CLASS.id()),
    );
    carry_resend(&mut properties, &content.props);
    push_attachment_properties(account_id, content, max_size, &mut properties);
    ExchangeObject {
        properties,
        conflict: None,
    }
}

pub(super) fn write_error(err: trc::Error) -> RopError {
    match err.as_ref() {
        EventType::Limit(LimitEvent::SizeRequest) => RopError::Code(ErrorCode::TOO_BIG),
        EventType::Limit(LimitEvent::Quota) => RopError::Code(ErrorCode::QUOTA_EXCEEDED),
        #[cfg(feature = "enterprise")]
        EventType::Limit(LimitEvent::TenantQuota) => RopError::Code(ErrorCode::QUOTA_EXCEEDED),
        _ => RopError::Internal(err.caused_by(trc::location!())),
    }
}

#[cfg(all(test, stalwart_tests))]
#[rustfmt::skip]
#[path = "../../../../../../../stalwart-tests/unit/exchange/src/mapi/emsmdb/message/save/tests.rs"]
mod tests;
