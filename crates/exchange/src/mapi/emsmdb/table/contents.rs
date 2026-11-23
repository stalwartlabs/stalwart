/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{RowContent, TableRow, decode_restriction, references};
use crate::{
    ews::calendar::invitation::within_limit,
    folders::FolderNode,
    mapi::{
        emsmdb::{
            execute::{MailboxView, RopContext, RopError},
            message::{
                ContentScope, MessageParent, default_message_flags,
                fai::{fai_props, holds_normal_fai_rows},
                fill_conversation_index,
                load::{LoadDepth, MAX_DECODED, embedded},
                normalize_follow_up, numbered_attachments,
                object_row::{CarriedParts, MESSAGE_CLASS_KEY, decoded_properties},
                push_attachment, push_categories, push_content, push_email_state,
                push_message_defaults, push_message_ids, push_scoped_content, row_content,
                row_value,
            },
            props::PropBag,
            state::TableObject,
            store::StoreGuids,
        },
        ids::{IdSpace, MapiId},
    },
    store::{
        FolderKind, FolderRef,
        folder::{FaiKind, FolderStore},
        named::AccountNamedProps,
        object::{ExchangeObject, ExchangeObjectStore},
    },
};
use common::{
    cache::{email::MessageRef, exchange::ExchangeAccountCache},
    storage::batch::{DocumentBatch, Lookup, MAX_BATCH_BYTES, MAX_BATCH_DOCUMENTS},
};
use email::{
    cache::email::MessageCacheAccess,
    message::{
        messagedata::{EmailMessageData, MetadataForm, MetadataValue},
        metadata::{MetadataRow, view::PartView},
    },
};
use exchange_proto::{
    convert::{
        ical::calendar_part_class,
        mime::{decodes_tnef, derive_envelope_props, tnef_envelope_props},
        model::PropBag as ContentBag,
    },
    mapi::{
        ErrorCode,
        prop::{OwnedPropValue, PropId, PropKey, PropKeyRef, PropTag, PropType, tags},
        restriction::Restriction,
    },
};
use groupware::cache::GroupwareCache;
use mail_parser::{Charset, Message, MessageParser};
use store::ValueKey;
use trc::AddContext;
use types::{
    collection::{Collection, SyncCollection},
    field::EmailField,
    type_state::DataType,
};

const METHOD_REPLY: &str = "REPLY";
const TNEF_ENVELOPE_FETCH: usize = 1024 * 1024;

const STATE_COLUMNS: [PropId; 18] = [
    tags::HAS_ATTACHMENTS.id(),
    tags::OBJECT_TYPE.id(),
    tags::MID.id(),
    tags::FOLDER_ID.id(),
    tags::PARENT_FOLDER_ID.id(),
    tags::ENTRY_ID.id(),
    tags::PARENT_ENTRY_ID.id(),
    tags::SOURCE_KEY.id(),
    tags::PARENT_SOURCE_KEY.id(),
    tags::INSTANCE_KEY.id(),
    tags::INST_ID.id(),
    tags::INSTANCE_NUM.id(),
    tags::MESSAGE_FLAGS.id(),
    tags::READ.id(),
    tags::MESSAGE_SIZE.id(),
    tags::MESSAGE_DELIVERY_TIME.id(),
    tags::CREATION_TIME.id(),
    tags::LAST_MODIFICATION_TIME.id(),
];

const ID_COLUMNS: [PropId; 11] = [
    tags::OBJECT_TYPE.id(),
    tags::MID.id(),
    tags::FOLDER_ID.id(),
    tags::PARENT_FOLDER_ID.id(),
    tags::ENTRY_ID.id(),
    tags::PARENT_ENTRY_ID.id(),
    tags::SOURCE_KEY.id(),
    tags::PARENT_SOURCE_KEY.id(),
    tags::INSTANCE_KEY.id(),
    tags::INST_ID.id(),
    tags::INSTANCE_NUM.id(),
];

fn id_column(tag: PropTag) -> bool {
    ID_COLUMNS.contains(&tag.id())
}

pub fn state_column(tag: PropTag) -> bool {
    STATE_COLUMNS.contains(&tag.id())
}

pub fn envelope_column(tag: PropTag) -> bool {
    !state_column(tag)
}

pub fn mail_envelope_column(tag: PropTag) -> bool {
    !state_column(tag) && tag.id() != tags::BODY.id()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RowFill {
    State,
    Envelope,
}

impl TableObject {
    pub fn envelope_in_columns(&self) -> bool {
        !self.columns.iter().all(|tag| state_column(PropTag(*tag)))
    }

    pub fn ids_in_order(&self) -> Result<bool, RopError> {
        Ok(self
            .sort
            .iter()
            .any(|column| id_column(PropTag(column.tag)))
            || decode_restriction(&self.restriction)?
                .is_some_and(|restriction| references(&restriction, id_column)))
    }

    pub fn column_fill(&self) -> RowFill {
        if self.envelope_in_columns() {
            RowFill::Envelope
        } else {
            RowFill::State
        }
    }

    pub fn envelope_column(&self) -> fn(PropTag) -> bool {
        match self.folder.id().and_then(MapiId::to_node) {
            Some(FolderNode::Stored(FolderRef {
                kind: FolderKind::Mailbox,
                ..
            })) => mail_envelope_column,
            _ => envelope_column,
        }
    }

    pub fn envelope_in_order(&self, restriction: Option<&Restriction<'_>>) -> bool {
        let envelope_column = self.envelope_column();
        self.sort
            .iter()
            .chain(
                self.categories
                    .iter()
                    .filter_map(|categories| categories.maximum.as_ref()),
            )
            .any(|column| envelope_column(PropTag(column.tag)))
            || restriction.is_some_and(|restriction| references(restriction, envelope_column))
    }
}

impl RopContext<'_, '_> {
    pub(super) async fn contents_rows(
        &mut self,
        table: &TableObject,
        associated: bool,
        content: RowContent,
        envelope: bool,
    ) -> Result<Vec<TableRow>, RopError> {
        let mailbox_id = table.folder.mailbox_id;
        let folder = table.folder.id().ok_or(ErrorCode::OBJECT_DELETED)?;
        let node = folder.to_node().ok_or(ErrorCode::OBJECT_DELETED)?;
        let (normal_fai, search) = {
            let tree = self.folder_tree(mailbox_id).await?;
            let entry = tree.get(node).ok_or(ErrorCode::OBJECT_DELETED)?;
            (holds_normal_fai_rows(entry), entry.search)
        };
        if associated {
            return self
                .fai_rows(table, node, FaiKind::Associated, content)
                .await;
        }
        let FolderNode::Stored(FolderRef {
            kind,
            id: container,
        }) = node
        else {
            return if normal_fai {
                self.fai_rows(table, node, FaiKind::Normal, content).await
            } else {
                Ok(Vec::new())
            };
        };
        let mailbox = self.mailbox(mailbox_id).await?;
        let guids = StoreGuids::new(mailbox.exchange.store_instance, mailbox_id);
        let parent_ids = MessageParent::new(&guids, &mailbox.exchange, folder);
        let ids = content != RowContent::Keys && table.ids_in_order()?;
        let mut rows = Vec::new();
        match kind {
            FolderKind::Mailbox => {
                let Some(messages) = mailbox.messages.as_ref() else {
                    return Ok(rows);
                };
                for item in messages.in_mailbox(container) {
                    let id = MapiId::new(
                        IdSpace::Email,
                        mailbox.email_item(container, item.document_id()),
                    );
                    let key = id.counter();
                    let mut bag = PropBag::default();
                    if ids {
                        push_message_ids(&mut bag, &guids, &parent_ids, id);
                        push_row_instance(&mut bag, id);
                    }
                    if content != RowContent::Keys {
                        push_email_state(&mut bag, item, &mailbox.exchange);
                        push_categories(&mut bag, &mailbox, item);
                    }
                    rows.push(TableRow { key, bag });
                }
                if envelope && content != RowContent::Keys {
                    self.complete_rows(table, &mut rows, RowFill::Envelope)
                        .await?;
                }
            }
            FolderKind::Calendar | FolderKind::AddressBook => {
                let (collection, data_type) = if kind == FolderKind::Calendar {
                    (SyncCollection::Calendar, DataType::CalendarEvent)
                } else {
                    (SyncCollection::AddressBook, DataType::ContactCard)
                };
                if !self.types.contains(data_type) {
                    return Ok(rows);
                }
                let resources = self
                    .request
                    .server
                    .fetch_groupware_resources(mailbox_id, mailbox_id, collection)
                    .await
                    .caused_by(trc::location!())?;
                let rights = self.view_rights(mailbox_id).await?;
                let folder = FolderRef {
                    kind,
                    id: container,
                };
                for document_id in resources.children_ids(container) {
                    if rights.hides(&resources, document_id) {
                        continue;
                    }
                    let id = mailbox.client_item(folder, document_id);
                    let key = id.counter();
                    let mut bag = PropBag::default();
                    if ids {
                        push_message_ids(&mut bag, &guids, &parent_ids, id);
                        push_row_instance(&mut bag, id);
                    }
                    rows.push(TableRow { key, bag });
                }
                if envelope && content != RowContent::Keys {
                    self.complete_rows(table, &mut rows, RowFill::Envelope)
                        .await?;
                }
            }
            FolderKind::Virtual if search => {
                rows = self
                    .search_rows(table, node, envelope && content != RowContent::Keys)
                    .await?;
            }
            FolderKind::Virtual if normal_fai => {
                rows = self.fai_rows(table, node, FaiKind::Normal, content).await?;
            }
            FolderKind::Virtual | FolderKind::FileNode => {}
        }
        Ok(rows)
    }

    async fn fai_rows(
        &mut self,
        table: &TableObject,
        node: FolderNode,
        kind: FaiKind,
        content: RowContent,
    ) -> Result<Vec<TableRow>, RopError> {
        let mailbox_id = table.folder.mailbox_id;
        let folder = table.folder.id().ok_or(ErrorCode::OBJECT_DELETED)?;
        let Ok(fai_folder) = self.fai_folder(mailbox_id, node) else {
            return Ok(Vec::new());
        };
        let mailbox = self.mailbox(mailbox_id).await?;
        let guids = StoreGuids::new(mailbox.exchange.store_instance, mailbox_id);
        let parent_ids = MessageParent::new(&guids, &mailbox.exchange, folder);
        let named = AccountNamedProps::new(&mailbox.exchange);
        let with_content = content != RowContent::Keys || kind == FaiKind::Normal;
        let mut rows = Vec::new();
        self.request
            .server
            .fai_messages(mailbox_id, fai_folder, |id, fai| {
                if FaiKind::from(&fai.kind) != kind {
                    return Ok(true);
                }
                let id = MapiId::new(IdSpace::Fai, id);
                let key = id.counter();
                let mut bag = PropBag::default();
                push_message_ids(&mut bag, &guids, &parent_ids, id);
                push_row_instance(&mut bag, id);
                if with_content {
                    push_scoped_content(&mut bag, &fai_props(fai).props, &named, ContentScope::Row);
                }
                rows.push(TableRow { key, bag });
                Ok(true)
            })
            .await
            .caused_by(trc::location!())?;
        Ok(rows)
    }

    pub async fn complete_rows(
        &mut self,
        table: &TableObject,
        rows: &mut [TableRow],
        fill: RowFill,
    ) -> Result<(), RopError> {
        let mailbox_id = table.folder.mailbox_id;
        let folder = table.folder.id().ok_or(ErrorCode::OBJECT_DELETED)?;
        let mailbox = self.mailbox(mailbox_id).await?;
        let guids = StoreGuids::new(mailbox.exchange.store_instance, mailbox_id);
        let parent_ids = MessageParent::new(&guids, &mailbox.exchange, folder);
        let folder_counter = table.folder.counter;
        for row in rows.iter_mut().filter(|row| !row.bag.contains(tags::MID)) {
            let Some(id) = MapiId::from_counter(row.key) else {
                continue;
            };
            push_message_ids(&mut row.bag, &guids, &parent_ids, id);
            push_row_instance(&mut row.bag, id);
            if let Some(stored) = mailbox.stored_item(folder_counter, id)
                && stored.space == IdSpace::Email
                && !row.bag.contains(tags::MESSAGE_FLAGS)
                && let Some(item) = mailbox
                    .messages
                    .as_ref()
                    .and_then(|messages| messages.email_by_id(&stored.id))
            {
                push_email_state(&mut row.bag, item, &mailbox.exchange);
                push_categories(&mut row.bag, &mailbox, item);
            }
        }
        if fill == RowFill::State {
            return Ok(());
        }
        let mut missing = rows
            .iter()
            .filter(|row| !row.bag.contains(tags::MESSAGE_CLASS))
            .filter_map(|row| {
                MapiId::from_counter(row.key).and_then(|id| mailbox.stored_item(folder_counter, id))
            })
            .filter(|stored| {
                stored.space == IdSpace::Email
                    && !self.envelopes.contains_key(&(mailbox_id, stored.counter()))
            })
            .collect::<Vec<_>>();
        if !missing.is_empty() {
            missing.sort_unstable();
            missing.dedup();
            self.email_envelopes(&mailbox, &missing).await?;
        }
        let named = AccountNamedProps::new(&mailbox.exchange);
        for row in rows {
            if row.bag.contains(tags::MESSAGE_CLASS) {
                continue;
            }
            let Some(stored) = MapiId::from_counter(row.key)
                .and_then(|id| mailbox.stored_item(folder_counter, id))
            else {
                continue;
            };
            let key = (mailbox_id, stored.counter());
            if !self.envelopes.contains_key(&key) {
                let item = mailbox
                    .messages
                    .as_ref()
                    .filter(|_| stored.space == IdSpace::Email)
                    .and_then(|messages| messages.email_by_id(&stored.id));
                let envelope = self
                    .envelope(mailbox_id, &mailbox.exchange, stored, item)
                    .await?;
                self.envelopes.insert(key, envelope);
            }
            if let Some(envelope) = self.envelopes.get(&key) {
                push_content(&mut row.bag, envelope, &named);
                if stored.space == IdSpace::Email {
                    normalize_follow_up(&mut row.bag);
                }
                push_message_defaults(&mut row.bag);
            }
        }
        Ok(())
    }

    async fn email_envelopes(
        &mut self,
        mailbox: &MailboxView,
        missing: &[MapiId],
    ) -> Result<(), RopError> {
        let mailbox_id = mailbox.id;
        let mut batch = DocumentBatch::new(MAX_BATCH_BYTES);
        let mut built = Vec::with_capacity(missing.len().min(MAX_BATCH_DOCUMENTS));
        for chunk in missing.chunks(MAX_BATCH_DOCUMENTS) {
            batch.reset();
            for stored in chunk {
                batch.request(stored.id);
            }
            loop {
                self.request
                    .server
                    .read_metadata_batch(mailbox_id, MetadataForm::Row, &mut batch)
                    .await
                    .caused_by(trc::location!())?;
                for stored in chunk {
                    let metadata = match batch.lookup(stored.id) {
                        Lookup::Found(MetadataValue::Row(metadata)) => Some(metadata),
                        Lookup::Found(MetadataValue::Structure(_)) | Lookup::Missing => None,
                        Lookup::Skip => continue,
                    };
                    let item = mailbox
                        .messages
                        .as_ref()
                        .and_then(|messages| messages.email_by_id(&stored.id));
                    let envelope = self
                        .email_envelope(mailbox_id, &mailbox.exchange, *stored, item, metadata)
                        .await?;
                    built.push(((mailbox_id, stored.counter()), envelope));
                }
                if !batch.next_round() {
                    break;
                }
            }
            self.envelopes.extend(built.drain(..));
        }
        Ok(())
    }

    async fn envelope(
        &mut self,
        mailbox_id: u32,
        exchange: &ExchangeAccountCache,
        id: MapiId,
        item: Option<MessageRef<'_>>,
    ) -> Result<ContentBag, RopError> {
        if id.space != IdSpace::Email {
            return match self.load_message(mailbox_id, id, LoadDepth::Envelope).await {
                Ok(message) => {
                    let flags = default_message_flags(&message);
                    let mut envelope = row_content(message.props);
                    if envelope
                        .get(PropKeyRef::Tag(tags::MESSAGE_FLAGS.id()), PropType::I32)
                        .is_none()
                    {
                        envelope.set(
                            PropKey::tag(tags::MESSAGE_FLAGS.id()),
                            OwnedPropValue::I32(flags),
                        );
                    }
                    Ok(envelope)
                }
                Err(RopError::Code(_)) => Ok(ContentBag::new()),
                Err(err) => Err(err),
            };
        }
        let metadata = self
            .request
            .server
            .store()
            .get_value::<MetadataRow>(ValueKey::immutable(
                mailbox_id,
                Collection::Email,
                id.id,
                EmailField::Metadata,
            ))
            .await
            .caused_by(trc::location!())?;
        self.email_envelope(mailbox_id, exchange, id, item, metadata.as_ref())
            .await
    }

    async fn email_envelope(
        &self,
        mailbox_id: u32,
        exchange: &ExchangeAccountCache,
        id: MapiId,
        item: Option<MessageRef<'_>>,
        metadata: Option<&MetadataRow>,
    ) -> Result<ContentBag, RopError> {
        let mut envelope = ContentBag::new();
        let Some(metadata) = metadata else {
            return Ok(envelope);
        };
        let headers = metadata.raw_headers().caused_by(trc::location!())?;
        let object = if exchange.has_object(Collection::Email, id.id) {
            self.request
                .server
                .exchange_object(mailbox_id, Collection::Email, id.id)
                .await
                .caused_by(trc::location!())?
        } else {
            None
        };
        let row = object
            .as_ref()
            .and_then(|object| match object.unarchive::<ExchangeObject>() {
                Ok(row) => Some(row),
                Err(err) => {
                    trc::error!(
                        err.account_id(mailbox_id)
                            .document_id(id.id)
                            .details("Skipping unreadable MAPI Object row in a contents table")
                            .caused_by(trc::location!())
                    );
                    None
                }
            });
        let calendar = if row.is_some_and(|row| row.property(&MESSAGE_CLASS_KEY).is_some()) {
            None
        } else {
            self.calendar_class(mailbox_id, id.id, metadata).await?
        };
        if let Some(parsed) = MessageParser::new().parse_headers(headers.as_ref()) {
            derive_envelope_props(&parsed, calendar, &mut envelope);
            if decodes_tnef(&parsed) {
                self.merge_tnef(mailbox_id, id.id, metadata, &parsed, &mut envelope)
                    .await?;
            }
        }
        if let Some(row) = row {
            let mut parts = CarriedParts::default();
            for (key, value) in decoded_properties(row.properties.iter()) {
                if let Some(value) = parts.take(key.as_ref(), value) {
                    let value = row_value(key.as_ref(), value);
                    envelope.set(key, value);
                }
            }
            parts.apply_envelope(&mut envelope);
        }
        if let Some(item) = item {
            fill_conversation_index(&mut envelope, item);
        }
        Ok(envelope)
    }

    async fn calendar_class(
        &self,
        account_id: u32,
        document_id: u32,
        row: &MetadataRow,
    ) -> trc::Result<Option<&'static str>> {
        let meta = row.unarchive().caused_by(trc::location!())?;
        let Some((part, method)) = meta
            .root()
            .parts()
            .find(|part| {
                part.content_type().is_some_and(|content| {
                    content.ctype().eq_ignore_ascii_case("text")
                        && content
                            .subtype()
                            .is_some_and(|subtype| subtype.eq_ignore_ascii_case("calendar"))
                })
            })
            .and_then(|part| {
                let method = part.content_type()?.attribute("method")?;
                Some((part, method))
            })
        else {
            return Ok(None);
        };
        if !method.trim().eq_ignore_ascii_case(METHOD_REPLY) {
            return Ok(calendar_part_class(method, None));
        }
        let server = self.request.server;
        let Some(range) = meta
            .blob_range(part.body_range())
            .filter(|_| within_limit(&part, server.core.groupware.itip_inbound_max_ical_size))
        else {
            return Ok(calendar_part_class(method, None));
        };
        let size = u64::try_from(range.len()).ok();
        let body = match server.fetch_blob(&meta.blob_hash(), range, size).await {
            Ok(body) => body,
            Err(err) => {
                trc::error!(
                    err.account_id(account_id)
                        .document_id(document_id)
                        .details("Skipping the iMIP reply status of a MAPI contents row")
                        .caused_by(trc::location!())
                );
                None
            }
        };
        let Some(body) = body else {
            return Ok(calendar_part_class(method, None));
        };
        let (decoded, _) = part.encoding().decode_checked(&body);
        let charset = part
            .charset()
            .and_then(|label| Charset::from_label(label.as_bytes()))
            .unwrap_or_default();
        let (text, _) = charset.decode_checked(&decoded);
        Ok(calendar_part_class(method, Some(text.as_ref())))
    }

    async fn merge_tnef(
        &self,
        account_id: u32,
        document_id: u32,
        metadata: &MetadataRow,
        parsed: &Message<'_>,
        envelope: &mut ContentBag,
    ) -> trc::Result<()> {
        let meta = metadata.unarchive().caused_by(trc::location!())?;
        let Some((encoding, range)) = meta
            .root()
            .attachments()
            .find(is_tnef)
            .and_then(|part| Some((part.encoding(), meta.blob_range(part.body_range())?)))
        else {
            return Ok(());
        };
        let end = range
            .end
            .min(range.start.saturating_add(TNEF_ENVELOPE_FETCH));
        let range = range.start..end;
        let size = u64::try_from(range.len()).ok();
        let blob = match self
            .request
            .server
            .fetch_blob(&meta.blob_hash(), range, size)
            .await
        {
            Ok(Some(blob)) => blob,
            Ok(None) => return Ok(()),
            Err(err) => {
                trc::error!(
                    err.account_id(account_id)
                        .document_id(document_id)
                        .details("Skipping the winmail.dat properties of a MAPI contents row")
                        .caused_by(trc::location!())
                );
                return Ok(());
            }
        };
        let Some(props) = tnef_envelope_props(parsed, &encoding.decode(&blob), MAX_DECODED) else {
            return Ok(());
        };
        for (key, value) in props.into_entries() {
            if envelope.get_any(key.as_ref()).is_none() {
                let value = row_value(key.as_ref(), value);
                envelope.set(key, value);
            }
        }
        Ok(())
    }

    pub(super) async fn attachment_rows(
        &mut self,
        table: &TableObject,
        content: RowContent,
    ) -> Result<Vec<TableRow>, RopError> {
        let message = table.message.as_ref().ok_or(ErrorCode::NULL_OBJECT)?;
        let root = self.message_root(message).await?;
        let parent = embedded(&root, &message.path).ok_or(ErrorCode::OBJECT_DELETED)?;
        let mailbox = self.mailbox(message.mailbox_id).await?;
        let named = AccountNamedProps::new(&mailbox.exchange);
        let mid = message
            .id()
            .map(|id| i64::from_le_bytes(id.to_client_message().to_eid().to_wire()));
        let mut rows = Vec::with_capacity(parent.attachments.len());
        for (number, item) in numbered_attachments(parent) {
            let mut bag = PropBag::default();
            if content != RowContent::Keys {
                if let Some(mid) = mid {
                    bag.push_i64(tags::MID, mid);
                }
                push_attachment(&mut bag, number, item);
                push_content(&mut bag, &item.props, &named);
            }
            rows.push(TableRow {
                key: u64::from(number),
                bag,
            });
        }
        Ok(rows)
    }
}

pub fn push_row_instance(bag: &mut PropBag, id: MapiId) {
    bag.push_i64(
        tags::INST_ID,
        i64::from_le_bytes(id.to_client_message().to_eid().to_wire()),
    );
    bag.push_i32(tags::INSTANCE_NUM, 0);
}

fn is_tnef(part: &PartView<'_>) -> bool {
    part.content_type().is_some_and(|content_type| {
        content_type.ctype().eq_ignore_ascii_case("application")
            && content_type
                .subtype()
                .is_some_and(|subtype| subtype.eq_ignore_ascii_case("ms-tnef"))
    }) || part
        .attachment_name()
        .is_some_and(|name| name.eq_ignore_ascii_case("winmail.dat"))
}
