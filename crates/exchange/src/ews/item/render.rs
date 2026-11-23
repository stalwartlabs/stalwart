/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{
    EmailIds, MailItem,
    attachment::attachment_list,
    create::{DISPOSITION_NOTIFICATION_TO, RETURN_RECEIPT_TO},
    fields::{ItemFieldSet, ShapeUse},
    props::{ItemProp, is_carried},
    update::{FLAG_STATUS_COMPLETED, FLAG_STATUS_FLAGGED},
};
use crate::{
    eas::convert::{
        body::{TextKind, message_text_body},
        flag::{
            FLAG_STATUS_ACTIVE, FLAG_STATUS_COMPLETE, FlagKeys, StoredFlags, StoredMail,
            rendered_flag,
        },
    },
    ews::{
        calendar::invitation::{MeetingMethod, meeting_part, within_limit},
        delegate::Principal,
        filter::PropValue,
        folder::{folder_id, props::change_time},
    },
    folders::FolderNode,
    mail::AccountCategories,
    mapi::emsmdb::message::object_row::encode_key,
    rules::map::FORWARDED_BY_HEADER,
    store::{
        FolderKind, FolderRef,
        object::{ExchangeObject, ExchangeObjectStore},
    },
};
use bytes::Bytes;
use common::{
    MessageStoreCache, Server, cache::exchange::ExchangeAccountCache, storage::blob::FetchedBlob,
};
use compact_str::CompactString;
use email::{
    cache::email::MessageCacheAccess,
    message::metadata::{
        AddressHeader, Addresses, ArchivedMessageMetadata, HeaderId, Mailbox, MessageView,
        MetadataRow, Occurrence, PartKind, PartSource, PartView, RawMessage,
    },
};
use exchange_proto::{
    common::time::UtcSeconds,
    convert::{conversation::ConversationIndex, ical::reply_class},
    eas::{commands::appdata::email::EmailFlag, types::EasDateTime},
    ews::{
        html::HtmlFilter,
        schema::{BodyType, BodyTypeResponse, FlagStatus, Importance, MailboxType, Sensitivity},
        types::{
            address::{EmailAddress, Recipients, SingleRecipient},
            common::{Body, Flag, InternetHeader, InternetHeaders},
            item::{
                Item, ItemFields, MeetingCancellationItem, MeetingRequestItem, MeetingResponseItem,
                MessageFields, MessageItem, MimeContent,
            },
            path::Path,
            shape::ItemShape,
            value::{DateTime, Repeated, Strings, XBinary},
            xprop::{ExtendedFieldUri, ExtendedProperty, XPropValue},
        },
    },
    mapi::prop::{OwnedPropValue, PropType},
};
use jiff::Timestamp;
use std::borrow::Cow;
use store::{ValueKey, roaring::RoaringBitmap};
use trc::AddContext;
use types::{
    collection::Collection,
    field::EmailField,
    keyword::{ANSWERED, DELETED, DRAFT, FLAGGED, FORWARDED, SEEN},
};

pub(super) const MESSAGE_CLASS: &str = "IPM.Note";
const MEETING_REQUEST_CLASS: &str = "IPM.Schedule.Meeting.Request";
const MEETING_CANCELLATION_CLASS: &str = "IPM.Schedule.Meeting.Canceled";
const CONTENT_CLASS: &str = "urn:content-classes:message";
const MSGFLAG_READ: i64 = 0x01;
const MSGFLAG_UNSENT: i64 = 0x08;
const MSGFLAG_HASATTACH: i64 = 0x10;
const VERB_REPLY: i64 = 102;
const VERB_FORWARD: i64 = 104;
const IMAP_DELETED: i64 = 1;
const ROUTING_SMTP: &str = "SMTP";

enum XPropSource {
    Mapped(ItemProp),
    Carried { key: Vec<u8>, ptype: PropType },
}

pub(crate) struct MailShape<'r> {
    pub fields: ItemFieldSet,
    receiver: Option<Principal>,
    extended: Vec<(&'r ExtendedFieldUri<'r>, XPropSource)>,
    carried: bool,
    flags: Option<FlagKeys>,
    body_type: BodyTypeResponse,
    html: HtmlContent,
    max_body_size: Option<usize>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DisplayNames {
    Header,
    Resolved,
}

pub(super) enum HtmlContent {
    Unfiltered,
    Filtered(Box<HtmlFilter>),
}

impl HtmlContent {
    pub(super) fn requested(filter: bool) -> Self {
        if filter {
            HtmlContent::Filtered(Box::default())
        } else {
            HtmlContent::Unfiltered
        }
    }
}

impl<'r> MailShape<'r> {
    pub fn new(shape: &'r ItemShape<'r>, usage: ShapeUse) -> Self {
        let extended = shape
            .additional
            .iter()
            .filter_map(|path| match path {
                Path::Extended(uri) => Some((uri, XPropSource::of(uri)?)),
                _ => None,
            })
            .collect::<Vec<_>>();
        let fields = ItemFieldSet::from_shape(shape, usage);
        let flags = (fields
            .has(ItemFieldSet::FLAG | ItemFieldSet::RESPONSE_REQUESTED | ItemFieldSet::CLASS)
            || extended.iter().any(|(_, source)| {
                matches!(
                    source,
                    XPropSource::Mapped(
                        ItemProp::FlagStatus | ItemProp::LastVerb | ItemProp::ItemClass
                    )
                )
            }))
        .then(FlagKeys::new);
        let body_type = shape.body_type.unwrap_or(BodyTypeResponse::Best);
        MailShape {
            html: HtmlContent::requested(
                shape.filter_html
                    && fields.has(ItemFieldSet::BODY)
                    && body_type != BodyTypeResponse::Text,
            ),
            fields,
            receiver: None,
            carried: extended
                .iter()
                .any(|(_, source)| matches!(source, XPropSource::Carried { .. })),
            flags,
            extended,
            body_type,
            max_body_size: shape
                .max_body_size
                .and_then(|size| usize::try_from(size).ok()),
        }
    }

    pub fn id_only() -> Self {
        Self::probe(ItemFieldSet::id_only())
    }

    pub fn mime_only() -> Self {
        Self::probe(ItemFieldSet::mime_only())
    }

    pub fn metadata_only() -> Self {
        Self::probe(ItemFieldSet::with_metadata())
    }

    pub fn classified() -> Self {
        Self::probe(ItemFieldSet::classified())
    }

    pub fn search_results() -> Self {
        Self::probe(ItemFieldSet::search_results())
    }

    fn probe(fields: ItemFieldSet) -> Self {
        MailShape {
            fields,
            receiver: None,
            extended: Vec::new(),
            carried: false,
            flags: None,
            body_type: BodyTypeResponse::Best,
            html: HtmlContent::Unfiltered,
            max_body_size: None,
        }
    }

    fn mapped(&self) -> impl Iterator<Item = ItemProp> + '_ {
        self.extended.iter().filter_map(|(_, source)| match source {
            XPropSource::Mapped(prop) => Some(*prop),
            XPropSource::Carried { .. } => None,
        })
    }

    fn needs_row(&self) -> bool {
        self.carried || self.flags.is_some()
    }

    pub async fn load_receiver(&mut self, server: &Server, account_id: u32) -> trc::Result<()> {
        if self
            .fields
            .has(ItemFieldSet::RECEIVED_BY | ItemFieldSet::RECEIVED_REPRESENTING)
        {
            self.receiver = Principal::load_user(server, account_id).await?;
        }
        Ok(())
    }

    pub fn reads_carried(&self) -> bool {
        self.carried
    }

    pub async fn stored_flags(
        &self,
        server: &Server,
        account_id: u32,
        exchange: &ExchangeAccountCache,
        documents: impl Iterator<Item = u32>,
    ) -> trc::Result<StoredFlags> {
        if self.flags.is_none() {
            return Ok(StoredFlags::default());
        }
        StoredFlags::load(
            server,
            exchange,
            account_id,
            &documents.collect::<RoaringBitmap>(),
        )
        .await
    }

    fn needs_metadata(&self) -> bool {
        self.fields.needs_metadata() || self.mapped().any(ItemProp::needs_metadata)
    }

    fn needs_blob(&self) -> bool {
        self.fields.needs_text() || self.fields.has(ItemFieldSet::MIME)
    }

    fn needs_class(&self) -> bool {
        self.fields.has(ItemFieldSet::CLASS)
            || self.mapped().any(|prop| prop == ItemProp::ItemClass)
    }
}

impl XPropSource {
    fn of(uri: &ExtendedFieldUri<'_>) -> Option<Self> {
        if let Some((_, prop)) = ItemProp::of_extended(uri) {
            return Some(XPropSource::Mapped(prop));
        }
        let (key, ptype) = uri.to_prop().ok()?;
        is_carried(uri, key.as_ref()).then(|| XPropSource::Carried {
            key: encode_key(key.as_ref()),
            ptype,
        })
    }
}

pub(crate) struct LoadedMail<'c> {
    pub item: MailItem,
    keywords: u32,
    change_id: u64,
    size: u32,
    received_at: u64,
    sent_at: i64,
    thread_id: u32,
    uid: Option<u32>,
    categories: &'c [CompactString],
    carried: Vec<(usize, OwnedPropValue)>,
    stored: Option<StoredMail>,
    row: Option<MetadataRow>,
    blob: Option<FetchedBlob>,
    reply_limit: Option<usize>,
}

impl<'c> LoadedMail<'c> {
    pub async fn load(
        server: &Server,
        account_id: u32,
        cache: &'c MessageStoreCache,
        item: MailItem,
        shape: &MailShape<'_>,
    ) -> trc::Result<Option<Self>> {
        let Some(message) = cache.email_by_id(&item.document_id) else {
            return Ok(None);
        };
        let mut mail = LoadedMail {
            item,
            keywords: message.keywords(),
            change_id: message.change_id(),
            size: message.size(),
            received_at: message.received_at(),
            sent_at: message.sent_at_absolute(),
            thread_id: message.thread_id(),
            uid: message.uid_in(item.mailbox_id),
            categories: cache.custom_keywords(message),
            carried: Vec::new(),
            stored: None,
            row: None,
            blob: None,
            reply_limit: shape
                .needs_class()
                .then_some(server.core.groupware.itip_inbound_max_ical_size),
        };
        if shape.needs_metadata() || shape.needs_blob() {
            let Some(row) = server
                .store()
                .get_value::<MetadataRow>(ValueKey::immutable(
                    account_id,
                    Collection::Email,
                    item.document_id,
                    EmailField::Metadata,
                ))
                .await
                .caused_by(trc::location!())?
            else {
                return Ok(None);
            };
            mail.row = Some(row);
            mail.fetch_content(server, shape.needs_blob()).await?;
        }
        Ok(Some(mail))
    }

    pub async fn load_carried(
        &mut self,
        server: &Server,
        account_id: u32,
        exchange: &ExchangeAccountCache,
        shape: &MailShape<'_>,
    ) -> trc::Result<()> {
        let document_id = self.item.document_id;
        if !shape.needs_row() || !exchange.has_object(Collection::Email, document_id) {
            return Ok(());
        }
        let Some(archive) = server
            .exchange_object(account_id, Collection::Email, document_id)
            .await
            .caused_by(trc::location!())?
        else {
            return Ok(());
        };
        let object = archive
            .unarchive::<ExchangeObject>()
            .caused_by(trc::location!())?;
        self.stored = shape.flags.as_ref().and_then(|keys| keys.read_mail(object));
        self.carried = shape
            .extended
            .iter()
            .enumerate()
            .filter_map(|(index, (_, source))| {
                let XPropSource::Carried { key, ptype } = source else {
                    return None;
                };
                let (value, tail) = OwnedPropValue::read_canonical(object.property(key)?)?;
                (tail.is_empty() && same_text_type(value.ptype(), *ptype)).then_some((index, value))
            })
            .collect();
        Ok(())
    }

    pub fn take_flags(&mut self, flags: &mut StoredFlags) {
        self.stored = flags.take(self.item.document_id);
    }

    pub async fn load_row(
        &mut self,
        server: &Server,
        account_id: u32,
        exchange: &ExchangeAccountCache,
        shape: &MailShape<'_>,
        flags: &mut StoredFlags,
    ) -> trc::Result<()> {
        if shape.reads_carried() {
            self.load_carried(server, account_id, exchange, shape).await
        } else {
            self.take_flags(flags);
            Ok(())
        }
    }

    fn flag(&self) -> EmailFlag<'_> {
        rendered_flag(
            self.has_keyword(FLAGGED),
            self.stored.as_ref().and_then(|stored| stored.flag.as_ref()),
        )
    }

    pub async fn resolve_reply(&mut self, server: &Server) -> trc::Result<()> {
        self.reply_limit = Some(server.core.groupware.itip_inbound_max_ical_size);
        self.fetch_content(server, false).await
    }

    pub async fn complete(&mut self, server: &Server, shape: &MailShape<'_>) -> trc::Result<()> {
        if shape.needs_class() {
            self.reply_limit = Some(server.core.groupware.itip_inbound_max_ical_size);
        }
        self.fetch_content(server, shape.needs_blob()).await
    }

    async fn fetch_content(&mut self, server: &Server, needs_blob: bool) -> trc::Result<()> {
        if self.blob.is_none()
            && (needs_blob || self.reply_limit.is_some())
            && let Some(row) = &self.row
        {
            let meta = row.unarchive().caused_by(trc::location!())?;
            if needs_blob || self.reply_part(meta).is_some() {
                self.blob = fetch_message(server, meta).await?;
            }
        }
        Ok(())
    }

    fn reply_part<'m>(&self, meta: &'m ArchivedMessageMetadata) -> Option<PartView<'m>> {
        let limit = self.reply_limit?;
        meeting_part(meta)
            .filter(|(method, part)| *method == MeetingMethod::Reply && within_limit(part, limit))
            .map(|(_, part)| part)
    }

    pub fn headers(&self) -> trc::Result<Cow<'_, [u8]>> {
        match &self.row {
            Some(row) => row.raw_headers().caused_by(trc::location!()),
            None => Ok(Cow::Borrowed(&[])),
        }
    }

    pub fn blob(&self) -> Option<&[u8]> {
        self.blob.as_deref()
    }

    pub fn meta(&self) -> trc::Result<Option<&ArchivedMessageMetadata>> {
        self.row
            .as_ref()
            .map(|row| row.unarchive().caused_by(trc::location!()))
            .transpose()
    }

    pub fn received(&self) -> Option<DateTime> {
        date_time(seconds(self.received_at))
    }

    fn has_keyword(&self, keyword: usize) -> bool {
        self.keywords & (1 << keyword) != 0
    }

    pub fn is_answered(&self) -> bool {
        self.has_keyword(ANSWERED)
    }

    pub fn value<'x>(&'x self, view: &'x MailView<'x>, prop: ItemProp) -> Option<PropValue<'x>> {
        Some(match prop {
            ItemProp::Size => PropValue::Int(i64::from(self.size)),
            ItemProp::Received => PropValue::Time(timestamp(seconds(self.received_at))?),
            ItemProp::Sent => PropValue::Time(timestamp(self.sent_at)?),
            ItemProp::IsRead => PropValue::Bool(self.has_keyword(SEEN)),
            ItemProp::ImapUid => PropValue::Int(i64::from(self.uid?)),
            ItemProp::FlagStatus => PropValue::Int(match self.flag().status {
                Some(FLAG_STATUS_ACTIVE) => FLAG_STATUS_FLAGGED,
                Some(FLAG_STATUS_COMPLETE) => FLAG_STATUS_COMPLETED,
                _ => return None,
            }),
            ItemProp::LastVerb => {
                PropValue::Int(match self.stored.as_ref().and_then(|stored| stored.verb) {
                    Some(state) => i64::from(state.verb.mapi()),
                    None if self.has_keyword(FORWARDED) => VERB_FORWARD,
                    None if self.has_keyword(ANSWERED) => VERB_REPLY,
                    None => return None,
                })
            }
            ItemProp::LastModified => return change_time(self.change_id),
            ItemProp::ContentClass => PropValue::Text(CONTENT_CLASS),
            ItemProp::ImapDeleted => {
                if !self.has_keyword(DELETED) {
                    return None;
                }
                PropValue::Int(IMAP_DELETED)
            }
            ItemProp::Keywords | ItemProp::ConversationIndex | ItemProp::Location => return None,
            ItemProp::MessageFlags => {
                let mut flags = 0;
                if self.has_keyword(SEEN) {
                    flags |= MSGFLAG_READ;
                }
                if self.has_keyword(DRAFT) {
                    flags |= MSGFLAG_UNSENT;
                }
                if view.has_attachments() {
                    flags |= MSGFLAG_HASATTACH;
                }
                PropValue::Int(flags)
            }
            ItemProp::Subject => PropValue::Text(view.meta?.root().envelope().subject()?),
            ItemProp::ItemClass => PropValue::Text(view.item_class()?),
            ItemProp::HasAttachments => PropValue::Bool(view.has_attachments()),
            ItemProp::Importance => PropValue::Text(view.importance().as_str()),
            ItemProp::From => PropValue::Text(
                view.addresses(AddressHeader::From)?
                    .mailboxes()
                    .next()?
                    .address?,
            ),
            ItemProp::To => PropValue::Text(view.to_text.as_deref()?),
            ItemProp::Cc => PropValue::Text(view.cc_text.as_deref()?),
            ItemProp::MessageId => {
                PropValue::Text(view.meta?.root().envelope().message_id().last_bracketed()?)
            }
            ItemProp::TransportHeaders => PropValue::Text(std::str::from_utf8(view.headers).ok()?),
        })
    }
}

pub(crate) struct MailView<'x> {
    meta: Option<&'x ArchivedMessageMetadata>,
    headers: &'x [u8],
    to_text: Option<String>,
    cc_text: Option<String>,
    kind: MailKind,
    stored_class: Option<&'x str>,
}

impl<'x> MailView<'x> {
    pub fn new(mail: &'x LoadedMail<'_>, headers: &'x [u8], joined: bool) -> trc::Result<Self> {
        let meta = mail.meta()?;
        let mut view = MailView {
            meta,
            headers,
            to_text: None,
            cc_text: None,
            kind: MailKind::Message,
            stored_class: mail
                .stored
                .as_ref()
                .and_then(|stored| stored.message_class.as_deref()),
        };
        view.kind = match meta.and_then(meeting_part) {
            None => MailKind::Message,
            Some((MeetingMethod::Request, _)) => MailKind::MeetingRequest,
            Some((MeetingMethod::Cancel, _)) => MailKind::MeetingCancellation,
            Some((MeetingMethod::Reply, part)) => {
                MailKind::MeetingResponse(match mail.reply_limit {
                    None => None,
                    Some(limit) if !within_limit(&part, limit) => Some(reply_class(None)),
                    Some(_) => {
                        let text = view
                            .source(mail)
                            .and_then(|(meta, raw)| meta.source(part.message(), raw))
                            .and_then(|source| part.text(&source));
                        Some(reply_class(text.as_ref().map(|text| text.text.as_ref())))
                    }
                })
            }
        };
        if joined {
            view.to_text = view.addresses(AddressHeader::To).map(joined_addresses);
            view.cc_text = view.addresses(AddressHeader::Cc).map(joined_addresses);
        }
        Ok(view)
    }

    pub fn source(
        &self,
        mail: &'x LoadedMail<'_>,
    ) -> Option<(&'x ArchivedMessageMetadata, RawMessage<'x>)> {
        let meta = self.meta?;
        Some((
            meta,
            meta.raw_message(Some(self.headers), mail.blob.as_deref()?),
        ))
    }

    fn kind(&self) -> MailKind {
        self.kind
    }

    pub(super) fn headers(&self) -> &'x [u8] {
        self.headers
    }

    pub(super) fn class(&self) -> Option<&'static str> {
        self.kind.class()
    }

    pub(super) fn item_class(&self) -> Option<&'x str> {
        self.stored_class.or_else(|| self.kind.class())
    }

    pub(super) fn topic(&self) -> Option<&'x str> {
        self.meta?
            .root()
            .envelope()
            .subject()
            .map(mail_parser::thread_name)
    }

    pub(super) fn message_id(&self) -> Option<&'x str> {
        self.meta?.root().envelope().message_id().last_bracketed()
    }

    pub(super) fn in_reply_to(&self) -> Option<&'x str> {
        self.meta?.root().envelope().in_reply_to().last_bracketed()
    }

    pub(super) fn sender_name(&self) -> Option<&'x str> {
        self.addresses(AddressHeader::From)?
            .mailboxes()
            .find_map(mailbox_name)
    }

    pub(super) fn recipient_names(&self) -> impl Iterator<Item = &'x str> {
        [AddressHeader::To, AddressHeader::Cc, AddressHeader::Bcc]
            .into_iter()
            .filter_map(|header| self.addresses(header))
            .flat_map(|addresses| addresses.mailboxes().filter_map(mailbox_name))
    }

    pub fn has_unresolved_class(&self) -> bool {
        self.stored_class.is_none() && matches!(self.kind, MailKind::MeetingResponse(None))
    }

    pub fn assume_reply_class(&mut self, class: &'static str) {
        if let MailKind::MeetingResponse(resolved) = &mut self.kind {
            *resolved = Some(class);
        }
    }

    pub(super) fn addresses(&self, header: AddressHeader) -> Option<Addresses<'x>> {
        self.meta
            .map(|meta| meta.root().envelope().addresses(header, Occurrence::Last))
    }

    pub(super) fn has_attachments(&self) -> bool {
        self.meta
            .is_some_and(|meta| meta.root().attachments().next().is_some())
    }

    fn header(&self, name: &str) -> Option<&'x [u8]> {
        let meta = self.meta?;
        let root = meta.root();
        root.root_part()
            .headers()
            .last_named(name, self.headers)
            .and_then(|header| header.raw_value(self.headers))
            .map(<[u8]>::trim_ascii)
    }

    pub(super) fn importance(&self) -> Importance {
        if let Some(importance) = self.header("Importance").and_then(|value| {
            hashify::map_ignore_case!(
                value,
                Importance,
                "low" => Importance::Low,
                "normal" => Importance::Normal,
                "high" => Importance::High,
            )
        }) {
            return *importance;
        }
        match self.header("X-Priority").and_then(<[u8]>::first) {
            Some(b'1' | b'2') => Importance::High,
            Some(b'4' | b'5') => Importance::Low,
            _ => Importance::Normal,
        }
    }

    pub(super) fn recipient_addresses(&self) -> impl Iterator<Item = &'x str> {
        [AddressHeader::To, AddressHeader::Cc]
            .into_iter()
            .filter_map(|header| self.addresses(header))
            .flat_map(|addresses| addresses.mailboxes().filter_map(|mailbox| mailbox.address))
    }

    fn is_delivered(&self) -> bool {
        self.meta.is_some_and(|meta| {
            meta.root()
                .root_part()
                .headers()
                .last(HeaderId::DELIVERED_TO)
                .is_some()
        })
    }

    pub(super) fn delegated_by(&self) -> Option<&'x str> {
        self.header(FORWARDED_BY_HEADER)
            .and_then(|value| str::from_utf8(value).ok())
    }

    fn header_text(&self, name: &str) -> Option<Cow<'x, str>> {
        let text = String::from_utf8_lossy(self.header(name)?);
        if text.contains(['\r', '\n']) {
            Some(Cow::Owned(text.split(['\r', '\n']).collect()))
        } else {
            Some(text)
        }
    }
}

pub(crate) fn render<'x>(
    shape: &'x MailShape<'x>,
    ids: &'x EmailIds,
    mail: &'x LoadedMail<'_>,
    view: &'x MailView<'x>,
    names: DisplayNames,
) -> Item<'x> {
    let fields = shape.fields;
    let mut item = ItemFields::default();
    let mut message = MessageFields::default();
    let envelope = view.meta.map(|meta| meta.root().envelope());
    let kind = view.kind();
    if fields.has(ItemFieldSet::ID) {
        item.item_id = Some(ids.item_id(mail.item, mail.change_id));
    }
    if fields.has(ItemFieldSet::PARENT) {
        item.parent_folder_id = Some(folder_id(
            ids.account_id(),
            FolderNode::Stored(FolderRef {
                kind: FolderKind::Mailbox,
                id: mail.item.mailbox_id,
            }),
            mail.change_id,
        ));
    }
    if fields.has(ItemFieldSet::CLASS) {
        item.item_class = view.item_class().map(Cow::Borrowed);
    }
    if fields.has(ItemFieldSet::SUBJECT) {
        item.subject = envelope
            .and_then(|envelope| envelope.subject())
            .map(Cow::Borrowed);
    }
    if fields.has(ItemFieldSet::SENSITIVITY) {
        item.sensitivity = Some(Sensitivity::Normal);
    }
    if fields.has(ItemFieldSet::RECEIVED) {
        item.date_time_received = date_time(seconds(mail.received_at));
    }
    if fields.has(ItemFieldSet::CREATED) {
        item.date_time_created = date_time(seconds(mail.received_at));
    }
    if fields.has(ItemFieldSet::SENT) {
        item.date_time_sent = date_time(mail.sent_at);
    }
    if fields.has(ItemFieldSet::SIZE) {
        item.size = Some(i32::try_from(mail.size).unwrap_or(i32::MAX));
    }
    if fields.has(ItemFieldSet::CATEGORIES) && AccountCategories::any(mail.categories) {
        item.categories = Some(Strings(
            AccountCategories::new(ids.exchange())
                .resolve(mail.categories)
                .collect(),
        ));
    }
    if fields.has(ItemFieldSet::IMPORTANCE) {
        item.importance = Some(view.importance());
    }
    if fields.has(ItemFieldSet::IN_REPLY_TO) {
        item.in_reply_to = view.header_text("In-Reply-To");
    }
    if fields.has(ItemFieldSet::IS_SUBMITTED) {
        item.is_submitted = Some(false);
    }
    if fields.has(ItemFieldSet::IS_DRAFT) {
        item.is_draft = Some(mail.has_keyword(DRAFT));
    }
    if fields.has(ItemFieldSet::IS_FROM_ME) {
        item.is_from_me = Some(false);
    }
    if fields.has(ItemFieldSet::IS_ASSOCIATED) {
        item.is_associated = Some(false);
    }
    if fields.has(ItemFieldSet::HAS_ATTACHMENTS) {
        item.has_attachments = Some(view.has_attachments());
    }
    if fields.has(ItemFieldSet::ATTACHMENTS) {
        item.attachments = view
            .meta
            .and_then(|meta| attachment_list(ids, mail.item, meta.root(), None, mail.received()));
    }
    if fields.has(ItemFieldSet::HEADERS) {
        item.internet_message_headers = Some(internet_headers(view.headers));
    }
    if names == DisplayNames::Header {
        if fields.has(ItemFieldSet::DISPLAY_TO) {
            item.display_to = view.addresses(AddressHeader::To).map(display_names);
        }
        if fields.has(ItemFieldSet::DISPLAY_CC) {
            item.display_cc = view.addresses(AddressHeader::Cc).map(display_names);
        }
    }
    if fields.has(ItemFieldSet::LAST_MODIFIED) {
        item.last_modified_time = change_time(mail.change_id).and_then(|value| match value {
            PropValue::Time(time) => Some(DateTime::utc(UtcSeconds(time.as_second()))),
            _ => None,
        });
    }
    if fields.has(ItemFieldSet::CONVERSATION_ID) {
        item.conversation_id = Some(ids.conversation_id(mail.thread_id));
    }
    if fields.has(ItemFieldSet::FLAG) {
        let flag = mail.flag();
        item.flag = Some(Flag {
            flag_status: Some(match flag.status {
                Some(FLAG_STATUS_ACTIVE) => FlagStatus::Flagged,
                Some(FLAG_STATUS_COMPLETE) => FlagStatus::Complete,
                _ => FlagStatus::NotFlagged,
            }),
            start_date: flag.utc_start_date.or(flag.start_date).map(flag_time),
            due_date: flag.utc_due_date.or(flag.due_date).map(flag_time),
            complete_date: flag.complete_time.or(flag.date_completed).map(flag_time),
        });
    }
    if fields.has(ItemFieldSet::PREVIEW) {
        item.preview = view.meta.map(|meta| Cow::Borrowed(meta.preview()));
    }
    if let Some((meta, raw)) = view.source(mail) {
        let source = PartSource::Raw(raw);
        if fields.has(ItemFieldSet::BODY) {
            item.body = Some(body(
                meta.root(),
                &source,
                shape.body_type,
                &shape.html,
                shape.max_body_size,
            ));
        }
        if fields.has(ItemFieldSet::TEXT_BODY) {
            item.text_body = Some(body(
                meta.root(),
                &source,
                BodyTypeResponse::Text,
                &HtmlContent::Unfiltered,
                shape.max_body_size,
            ));
        }
        if fields.has(ItemFieldSet::MIME)
            && let Some(whole) = raw.whole()
        {
            item.mime_content = Some(MimeContent {
                character_set: Some(Cow::Borrowed("UTF-8")),
                content: XBinary::Bytes(Bytes::from(whole.to_vec())),
            });
        }
    }
    if !shape.extended.is_empty() {
        let values = shape
            .extended
            .iter()
            .enumerate()
            .filter_map(|(index, (uri, source))| {
                let value = match source {
                    XPropSource::Mapped(ItemProp::Keywords)
                        if AccountCategories::any(mail.categories) =>
                    {
                        XPropValue::Multi(
                            AccountCategories::new(ids.exchange())
                                .resolve(mail.categories)
                                .collect(),
                        )
                    }
                    XPropSource::Mapped(prop) => {
                        XPropValue::Single(mail.value(view, *prop)?.to_text())
                    }
                    XPropSource::Carried { .. } => mail
                        .carried
                        .iter()
                        .find(|(carried, _)| *carried == index)
                        .map(|(_, value)| XPropValue::from_owned(value))
                        .filter(
                            |value| !matches!(value, XPropValue::Multi(list) if list.is_empty()),
                        )?,
                };
                Some(ExtendedProperty {
                    uri: (*uri).clone(),
                    value,
                })
            })
            .collect::<Vec<_>>();
        if !values.is_empty() {
            item.extended_property = Some(Repeated(values));
        }
    }

    if fields.has(ItemFieldSet::SENDER) {
        message.sender = view
            .addresses(AddressHeader::Sender)
            .and_then(single)
            .or_else(|| view.addresses(AddressHeader::From).and_then(single));
    }
    if fields.has(ItemFieldSet::FROM) {
        message.from = view.addresses(AddressHeader::From).and_then(single);
    }
    if fields.has(ItemFieldSet::TO) {
        message.to_recipients = view.addresses(AddressHeader::To).and_then(recipients);
    }
    if fields.has(ItemFieldSet::CC) {
        message.cc_recipients = view.addresses(AddressHeader::Cc).and_then(recipients);
    }
    if fields.has(ItemFieldSet::BCC) {
        message.bcc_recipients = view.addresses(AddressHeader::Bcc).and_then(recipients);
    }
    if fields.has(ItemFieldSet::REPLY_TO) {
        message.reply_to = view.addresses(AddressHeader::ReplyTo).and_then(recipients);
    }
    if fields.has(ItemFieldSet::READ_RECEIPT) {
        message.is_read_receipt_requested =
            Some(view.header(DISPOSITION_NOTIFICATION_TO).is_some());
    }
    if fields.has(ItemFieldSet::DELIVERY_RECEIPT) {
        message.is_delivery_receipt_requested = Some(view.header(RETURN_RECEIPT_TO).is_some());
    }
    if fields.has(ItemFieldSet::RESPONSE_REQUESTED) {
        message.is_response_requested = mail
            .stored
            .as_ref()
            .and_then(|stored| stored.response_requested);
    }
    if fields.has(ItemFieldSet::TOPIC) {
        message.conversation_topic = envelope
            .and_then(|envelope| envelope.subject())
            .map(|subject| Cow::Borrowed(mail_parser::thread_name(subject)));
    }
    if fields.has(ItemFieldSet::CONVERSATION_INDEX) {
        message.conversation_index = Some(XBinary::Bytes(
            ConversationIndex::resolve(
                view.header("Thread-Index"),
                UtcSeconds(seconds(mail.received_at)),
                mail.thread_id,
            )
            .into_bytes(),
        ));
    }
    if fields.has(ItemFieldSet::MESSAGE_ID) {
        message.internet_message_id = envelope
            .and_then(|envelope| envelope.message_id().last_bracketed())
            .map(Cow::Borrowed);
    }
    if fields.has(ItemFieldSet::IS_READ) {
        message.is_read = Some(mail.has_keyword(SEEN));
    }
    if fields.has(ItemFieldSet::REFERENCES) {
        message.references = view.header_text("References");
    }
    if let Some(receiver) = &shape.receiver
        && view.is_delivered()
    {
        let recipient = || {
            SingleRecipient(EmailAddress {
                name: Some(Cow::Borrowed(&receiver.name)),
                email_address: (!receiver.address.is_empty())
                    .then_some(Cow::Borrowed(receiver.address.as_str())),
                routing_type: Some(Cow::Borrowed(ROUTING_SMTP)),
                mailbox_type: Some(MailboxType::Mailbox),
                ..Default::default()
            })
        };
        if fields.has(ItemFieldSet::RECEIVED_BY) {
            message.received_by = Some(recipient());
        }
        if fields.has(ItemFieldSet::RECEIVED_REPRESENTING) && view.delegated_by().is_none() {
            message.received_representing = Some(recipient());
        }
    }
    match kind {
        MailKind::Message => Item::Message(Box::new(MessageItem { item, message })),
        MailKind::MeetingRequest => Item::MeetingRequest(Box::new(MeetingRequestItem {
            item,
            message,
            meeting: Default::default(),
            request: Default::default(),
        })),
        MailKind::MeetingResponse(_) => Item::MeetingResponse(Box::new(MeetingResponseItem {
            item,
            message,
            meeting: Default::default(),
            response: Default::default(),
        })),
        MailKind::MeetingCancellation => {
            Item::MeetingCancellation(Box::new(MeetingCancellationItem {
                item,
                message,
                meeting: Default::default(),
                cancellation: Default::default(),
            }))
        }
    }
}

#[derive(Clone, Copy)]
enum MailKind {
    Message,
    MeetingRequest,
    MeetingResponse(Option<&'static str>),
    MeetingCancellation,
}

impl MailKind {
    fn class(self) -> Option<&'static str> {
        match self {
            MailKind::Message => Some(MESSAGE_CLASS),
            MailKind::MeetingRequest => Some(MEETING_REQUEST_CLASS),
            MailKind::MeetingResponse(class) => class,
            MailKind::MeetingCancellation => Some(MEETING_CANCELLATION_CLASS),
        }
    }
}

async fn fetch_message(
    server: &Server,
    meta: &ArchivedMessageMetadata,
) -> trc::Result<Option<FetchedBlob>> {
    server
        .fetch_blob(&meta.blob_hash(), 0..usize::MAX, Some(meta.size() as u64))
        .await
        .caused_by(trc::location!())
}

fn flag_time(time: EasDateTime) -> DateTime {
    DateTime::Utc {
        seconds: time.0,
        millis: time.1,
    }
}

pub(super) fn seconds(value: u64) -> i64 {
    i64::try_from(value).unwrap_or(i64::MAX)
}

fn timestamp(seconds: i64) -> Option<Timestamp> {
    Timestamp::from_second(seconds).ok()
}

pub(super) fn date_time(seconds: i64) -> Option<DateTime> {
    Some(DateTime::utc(UtcSeconds(seconds)))
}

pub(super) fn body<'x>(
    message: MessageView<'_>,
    source: &PartSource<'_>,
    requested: BodyTypeResponse,
    content: &HtmlContent,
    max_size: Option<usize>,
) -> Body<'x> {
    let html = match requested {
        BodyTypeResponse::Html => true,
        BodyTypeResponse::Text => false,
        BodyTypeResponse::Best => message
            .html_body()
            .any(|part| part.kind() == PartKind::Html),
    };
    let mut text = message_text_body(
        message,
        source,
        if html {
            TextKind::Html
        } else {
            TextKind::Plain
        },
    );
    if html && let HtmlContent::Filtered(filter) = content {
        text = filter.filter(&text);
    }
    let is_truncated = match max_size {
        Some(max) if text.len() > max => {
            let mut cut = max;
            while !text.is_char_boundary(cut) {
                cut -= 1;
            }
            text.truncate(cut);
            Some(true)
        }
        _ => None,
    };
    Body {
        body_type: if html { BodyType::Html } else { BodyType::Text },
        is_truncated,
        text: Cow::Owned(text),
    }
}

pub(super) fn single<'x>(addresses: Addresses<'x>) -> Option<SingleRecipient<'x>> {
    addresses
        .mailboxes()
        .next()
        .map(|mailbox| SingleRecipient(email_address(mailbox)))
}

pub(super) fn recipients<'x>(addresses: Addresses<'x>) -> Option<Recipients<'x>> {
    let list = addresses.mailboxes().map(email_address).collect::<Vec<_>>();
    (!list.is_empty()).then_some(Recipients(list))
}

fn mailbox_name(mailbox: Mailbox<'_>) -> Option<&str> {
    mailbox
        .name
        .filter(|name| !name.is_empty())
        .or(mailbox.address)
}

fn email_address<'x>(mailbox: Mailbox<'x>) -> EmailAddress<'x> {
    EmailAddress {
        name: mailbox_name(mailbox).map(Cow::Borrowed),
        email_address: mailbox.address.map(Cow::Borrowed),
        routing_type: Some(Cow::Borrowed(ROUTING_SMTP)),
        mailbox_type: Some(MailboxType::OneOff),
        ..Default::default()
    }
}

fn display_names<'x>(addresses: Addresses<'_>) -> Cow<'x, str> {
    let mut out = String::new();
    for name in addresses.mailboxes().filter_map(mailbox_name) {
        if !out.is_empty() {
            out.push_str("; ");
        }
        out.push_str(name);
    }
    Cow::Owned(out)
}

fn joined_addresses(addresses: Addresses<'_>) -> String {
    let mut out = String::new();
    for mailbox in addresses.mailboxes() {
        for part in [mailbox.name, mailbox.address].into_iter().flatten() {
            if !out.is_empty() {
                out.push(' ');
            }
            out.push_str(part);
        }
    }
    out
}

pub(super) fn internet_headers(headers: &[u8]) -> InternetHeaders<'_> {
    let mut list = Vec::new();
    let mut lines = headers.split(|byte| *byte == b'\n').peekable();
    while let Some(line) = lines.next() {
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        if line.is_empty() {
            break;
        }
        let mut parts = line.splitn(2, |byte| *byte == b':');
        let (Some(name), Some(value)) = (parts.next(), parts.next()) else {
            continue;
        };
        let mut value = String::from_utf8_lossy(value.trim_ascii()).into_owned();
        while let Some(next) =
            lines.next_if(|next| next.first().is_some_and(|b| *b == b' ' || *b == b'\t'))
        {
            value.push(' ');
            value.push_str(&String::from_utf8_lossy(next.trim_ascii()));
        }
        list.push(InternetHeader {
            name: String::from_utf8_lossy(name.trim_ascii()),
            value: Cow::Owned(value),
        });
    }
    InternetHeaders(list)
}

fn same_text_type(stored: PropType, requested: PropType) -> bool {
    stored == requested
        || matches!(
            (stored, requested),
            (PropType::String8, PropType::Unicode)
                | (PropType::Unicode, PropType::String8)
                | (PropType::MvString8, PropType::MvUnicode)
                | (PropType::MvUnicode, PropType::MvString8)
        )
}
