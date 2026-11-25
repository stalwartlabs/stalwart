/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

mod folder;

use folder::{FolderMark, FolderRoot, FolderStep};

use super::{
    CONTEXT_BASE_CHARGE, TagFilter, TransferContext,
    content::{write_attachment_content, write_children, write_message_props},
    stream::{Fill, Versions, encoder_charge, fx},
    string_mode,
};
use crate::{
    mapi::{
        emsmdb::{
            access::ItemWrite,
            execute::{MailboxView, RopContext, RopError, RopResult},
            message::{attachment_at, load::embedded, message_bag},
            props::{PropBag, PropOut},
            staged::{attachment_size, content_size},
            state::{
                AttachmentObject, MessageObject, RecipientColumns, ServerObject, TransferKind,
                mail_container,
            },
            store::StoreGuids,
        },
        ids::{ChangeNumber, ChangeSpace, IdSpace, MapiId},
    },
    store::named::AccountNamedProps,
};
use email::cache::email::MessageCacheAccess;
use exchange_proto::{
    convert::model::MessageContent,
    ics::{
        flags::{FastTransferCopyFlags, FastTransferCopyToFlags, SendOptions},
        fx::{FxEncoder, Marker, tags as subobject},
    },
    mapi::{
        ErrorCode,
        prop::{NamedPropMap, PropValue, tags},
        rop::{
            DecodedRop,
            requests::{
                FastTransferSourceCopyMessages, FastTransferSourceCopyProperties,
                FastTransferSourceCopyTo,
            },
        },
    },
};
use types::type_state::DataType;

const COPY_MESSAGES_FLAGS: u8 = FastTransferCopyFlags::MOVE
    | FastTransferCopyFlags::UNUSED1
    | FastTransferCopyFlags::UNUSED2
    | FastTransferCopyFlags::BEST_BODY
    | FastTransferCopyFlags::SEND_ENTRY_ID;
const COPY_PROPERTIES_FLAGS: u8 = FastTransferCopyFlags::MOVE
    | FastTransferCopyFlags::UNUSED1
    | FastTransferCopyFlags::UNUSED2
    | FastTransferCopyFlags::UNUSED3;
const COPY_FOLDER_FLAGS: u8 = FastTransferCopyFlags::MOVE | FastTransferCopyFlags::COPY_SUBFOLDERS;
const COPY_TO_FLAGS: u32 = FastTransferCopyToFlags::MOVE
    | FastTransferCopyToFlags::UNUSED1
    | FastTransferCopyToFlags::UNUSED2
    | FastTransferCopyToFlags::UNUSED3
    | FastTransferCopyToFlags::UNUSED4
    | FastTransferCopyToFlags::UNUSED5
    | FastTransferCopyToFlags::BEST_BODY;
const SEND_OPTIONS_FLAGS: u8 = SendOptions::UNICODE
    | SendOptions::USE_CPID
    | SendOptions::RECOVER_MODE
    | SendOptions::FORCE_UNICODE
    | SendOptions::PARTIAL_ITEM
    | SendOptions::RESERVED1
    | SendOptions::RESERVED2;
const ID_CHARGE: u64 = 8;
const STEP_CHARGE: u64 = size_of::<FolderStep>() as u64;
const TAG_CHARGE: u64 = 2;

pub struct CopySource {
    items: CopyItems,
    filter: Option<TagFilter>,
    subobjects: Subobjects,
    identity: Identity,
    recovery: Recovery,
    cursor: usize,
    failed: Option<ErrorCode>,
    pub(super) encoder: FxEncoder,
}

enum CopyItems {
    Messages {
        mailbox_id: u32,
        folder: u64,
        ids: Box<[u64]>,
    },
    Message(Box<MessageObject>),
    Attachment(Box<AttachmentObject>),
    Folder {
        mailbox_id: u32,
        steps: Box<[FolderStep]>,
    },
}

impl CopyItems {
    fn is_message_root(&self) -> bool {
        matches!(self, CopyItems::Message(_))
    }
}

enum Unit {
    Message(MessageObject),
    Attachment(AttachmentObject),
    Folder(FolderMark),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Subobjects {
    Copy,
    Skip,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Identity {
    Send,
    Strip,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Recovery {
    Skip,
    Fail,
}

impl Recovery {
    fn of(send: SendOptions) -> Self {
        if send.contains(SendOptions::RECOVER_MODE) {
            Recovery::Skip
        } else {
            Recovery::Fail
        }
    }
}

enum Step {
    Written,
    Deferred,
}

impl CopySource {
    fn total(&self) -> usize {
        match &self.items {
            CopyItems::Messages { ids, .. } => ids.len(),
            CopyItems::Message(_) | CopyItems::Attachment(_) => 1,
            CopyItems::Folder { steps, .. } => steps.len(),
        }
    }

    fn unit(&self, code_page: u16) -> Option<Unit> {
        let object = |mailbox_id, folder, message| MessageObject {
            mailbox_id,
            folder,
            message,
            code_page,
            path: Vec::new(),
            staged: None,
            recipient_columns: RecipientColumns::Unannounced,
        };
        match &self.items {
            CopyItems::Messages {
                mailbox_id,
                folder,
                ids,
            } => ids
                .get(self.cursor)
                .map(|&message| Unit::Message(object(*mailbox_id, *folder, message))),
            CopyItems::Message(message) => {
                (self.cursor == 0).then(|| Unit::Message(message.as_ref().clone()))
            }
            CopyItems::Attachment(attachment) => {
                (self.cursor == 0).then(|| Unit::Attachment(attachment.as_ref().clone()))
            }
            CopyItems::Folder { mailbox_id, steps } => {
                steps.get(self.cursor).map(|step| match *step {
                    FolderStep::Message { folder, message } => {
                        Unit::Message(object(*mailbox_id, folder, message))
                    }
                    FolderStep::Folder(mark) => Unit::Folder(mark),
                })
            }
        }
    }

    fn fixed_charge(&self) -> u64 {
        let entries = match &self.items {
            CopyItems::Messages { ids, .. } => {
                u64::try_from(ids.len()).map_or(u64::MAX, |len| len.saturating_mul(ID_CHARGE))
            }
            CopyItems::Message(_) | CopyItems::Attachment(_) => 0,
            CopyItems::Folder { steps, .. } => {
                u64::try_from(steps.len()).map_or(u64::MAX, |len| len.saturating_mul(STEP_CHARGE))
            }
        };
        let tags = match &self.filter {
            Some(TagFilter::Exclude(ids) | TagFilter::Include(ids)) => {
                u64::try_from(ids.len()).unwrap_or(u64::MAX)
            }
            None => 0,
        };
        CONTEXT_BASE_CHARGE
            .saturating_add(entries)
            .saturating_add(tags.saturating_mul(TAG_CHARGE))
    }

    pub(super) fn charge(&self) -> u64 {
        self.fixed_charge()
            .saturating_add(encoder_charge(&self.encoder))
    }

    pub(super) fn fail(&mut self, code: ErrorCode) {
        self.failed = Some(code);
    }

    fn copies_attachments(&self) -> bool {
        self.subobjects == Subobjects::Copy
            && self
                .filter
                .as_ref()
                .filter(|_| self.items.is_message_root())
                .is_none_or(|filter| filter.allows(subobject::MESSAGE_ATTACHMENTS))
    }

    fn write(
        &mut self,
        message: &MessageObject,
        content: &MessageContent,
        bag: &PropBag,
        versions: Option<&Versions>,
        guids: &StoreGuids,
        names: &dyn NamedPropMap,
    ) -> Result<(), RopError> {
        let listed = match self.items {
            CopyItems::Message(_) | CopyItems::Attachment(_) => None,
            CopyItems::Messages { .. } | CopyItems::Folder { .. } => {
                Some(message.id().ok_or(ErrorCode::NOT_FOUND)?)
            }
        };
        let filter = self
            .filter
            .as_ref()
            .filter(|_| self.items.is_message_root());
        let encoder = &mut self.encoder;
        if let Some(id) = listed {
            encoder
                .marker(if id.space == IdSpace::Fai {
                    Marker::StartFaiMsg
                } else {
                    Marker::StartMessage
                })
                .map_err(fx)?;
            let mid = id.to_client_message().to_eid();
            encoder
                .prop(
                    tags::MID,
                    &PropValue::I64(i64::from_le_bytes(mid.to_wire())),
                    names,
                )
                .map_err(fx)?;
            if self.identity == Identity::Send {
                write_identity(encoder, id, bag, versions, guids, names)?;
            }
        }
        write_message_props(encoder, bag, &content.props, filter, None, names)?;
        if self.subobjects == Subobjects::Copy {
            write_children(encoder, content, filter, names, 0)?;
        }
        if listed.is_some() {
            encoder.marker(Marker::EndMessage).map_err(fx)?;
        }
        Ok(())
    }
}

impl RopContext<'_, '_> {
    pub async fn fast_transfer_source_copy_messages(
        &mut self,
        rop: &DecodedRop<'_>,
        request: &FastTransferSourceCopyMessages<'_>,
    ) -> RopResult {
        let flags = request.copy_flags;
        if flags.0 & !COPY_MESSAGES_FLAGS != 0 {
            return Err(RopError::Code(ErrorCode::INVALID_PARAM));
        }
        let encoder = self.copy_encoder(request.send_options)?;
        let parent = self.input(rop.header.input_handle)?;
        let folder = match self.state.get(parent) {
            Some(ServerObject::Folder(folder)) => *folder,
            Some(_) => return Err(RopError::Code(ErrorCode::NOT_SUPPORTED)),
            None => return Err(RopError::Code(ErrorCode::NULL_OBJECT)),
        };
        if !self.types.contains(DataType::Email) {
            return Err(RopError::Code(ErrorCode::ACCESS_DENIED));
        }
        self.require_folder_items(folder.mailbox_id, folder.counter)
            .await?;
        if mail_container(folder.counter).is_none() {
            return Err(RopError::Code(ErrorCode::NOT_SUPPORTED));
        }
        let folder_id = folder.id().ok_or(ErrorCode::OBJECT_DELETED)?;
        let (deletable, fai_deletable) = if flags.contains(FastTransferCopyFlags::MOVE) {
            (
                self.write_allowed(folder.mailbox_id, folder.counter, ItemWrite::Delete)
                    .await?,
                self.write_allowed(folder.mailbox_id, folder.counter, ItemWrite::Associated)
                    .await?,
            )
        } else {
            (true, true)
        };
        let mut ids = Vec::new();
        if deletable || fai_deletable {
            ids.reserve(request.message_ids.len());
            for eid in request.message_ids.iter() {
                let Some(id) = MapiId::from_eid(eid).filter(|id| !id.space.is_folder()) else {
                    continue;
                };
                let id = if id.space != IdSpace::Fai
                    && self
                        .message_in_folder(folder.mailbox_id, folder_id, id)
                        .await?
                {
                    deletable.then_some(id)
                } else {
                    id.from_client_fai().filter(|_| fai_deletable)
                };
                if let Some(id) = id {
                    ids.push(id.counter());
                }
            }
        }
        let source = CopySource {
            items: CopyItems::Messages {
                mailbox_id: folder.mailbox_id,
                folder: folder.counter,
                ids: ids.into_boxed_slice(),
            },
            filter: None,
            subobjects: Subobjects::Copy,
            identity: if flags.contains(FastTransferCopyFlags::SEND_ENTRY_ID) {
                Identity::Send
            } else {
                Identity::Strip
            },
            recovery: Recovery::of(request.send_options),
            cursor: 0,
            failed: None,
            encoder,
        };
        self.open_transfer(
            rop,
            parent,
            request.output_handle_index,
            folder,
            TransferKind::Source,
            TransferContext::Copy(Box::new(source)),
        )
    }

    pub async fn fast_transfer_source_copy_to(
        &mut self,
        rop: &DecodedRop<'_>,
        request: &FastTransferSourceCopyTo<'_>,
    ) -> RopResult {
        let flags = request.copy_flags;
        if flags.0 & !COPY_TO_FLAGS != 0 || flags.contains(FastTransferCopyToFlags::MOVE) {
            return Err(RopError::Code(ErrorCode::INVALID_PARAM));
        }
        self.open_content_source(
            rop,
            request.output_handle_index,
            request.level,
            request.send_options,
            TagFilter::new(request.property_tags.iter(), false),
        )
        .await
    }

    pub async fn fast_transfer_source_copy_properties(
        &mut self,
        rop: &DecodedRop<'_>,
        request: &FastTransferSourceCopyProperties<'_>,
    ) -> RopResult {
        let flags = request.copy_flags;
        if flags.0 & !COPY_PROPERTIES_FLAGS != 0 {
            return Err(RopError::Code(ErrorCode::INVALID_PARAM));
        }
        if flags.contains(FastTransferCopyFlags::MOVE) {
            return Err(RopError::Code(ErrorCode::NOT_IMPLEMENTED));
        }
        self.open_content_source(
            rop,
            request.output_handle_index,
            request.level,
            request.send_options,
            TagFilter::new(request.property_tags.iter(), true),
        )
        .await
    }

    async fn open_content_source(
        &mut self,
        rop: &DecodedRop<'_>,
        index: u8,
        level: u8,
        send: SendOptions,
        filter: TagFilter,
    ) -> RopResult {
        let encoder = self.copy_encoder(send)?;
        let parent = self.input(rop.header.input_handle)?;
        let subobjects = if level == 0 {
            Subobjects::Copy
        } else {
            Subobjects::Skip
        };
        let (items, folder) = match self.state.get(parent) {
            Some(ServerObject::Message(message)) => (
                CopyItems::Message(Box::new(message.without_columns())),
                message.folder(),
            ),
            Some(ServerObject::Attachment(attachment)) => (
                CopyItems::Attachment(attachment.clone()),
                attachment.message.folder(),
            ),
            Some(ServerObject::Folder(folder)) => {
                let folder = *folder;
                return self
                    .open_folder_source(
                        rop,
                        index,
                        folder,
                        FolderRoot::Content { filter, subobjects },
                        Recovery::of(send),
                        encoder,
                    )
                    .await;
            }
            Some(_) => return Err(RopError::Code(ErrorCode::NOT_SUPPORTED)),
            None => return Err(RopError::Code(ErrorCode::NULL_OBJECT)),
        };
        if !self.types.contains(DataType::Email) {
            return Err(RopError::Code(ErrorCode::ACCESS_DENIED));
        }
        let source = CopySource {
            items,
            filter: Some(filter),
            subobjects,
            identity: Identity::Strip,
            recovery: Recovery::of(send),
            cursor: 0,
            failed: None,
            encoder,
        };
        self.open_transfer(
            rop,
            parent,
            index,
            folder,
            TransferKind::Source,
            TransferContext::Copy(Box::new(source)),
        )
    }

    pub fn tell_version(&mut self, rop: &DecodedRop<'_>, index: u8) -> RopResult {
        match self.transfer_object(rop)?.kind {
            TransferKind::Source
            | TransferKind::Upload
            | TransferKind::Contents
            | TransferKind::Hierarchy => self.respond_empty(rop, index),
            TransferKind::StateStream
            | TransferKind::ContentsCollector
            | TransferKind::HierarchyCollector => Err(RopError::Code(ErrorCode::NOT_SUPPORTED)),
        }
    }

    fn copy_encoder(&self, send: SendOptions) -> Result<FxEncoder, RopError> {
        if send.0 & !SEND_OPTIONS_FLAGS != 0 {
            return Err(RopError::Code(ErrorCode::INVALID_PARAM));
        }
        Ok(FxEncoder::new(string_mode(send, self.code_page())))
    }

    pub(super) async fn produce_copy(
        &mut self,
        source: &mut CopySource,
        budget: usize,
    ) -> Result<Fill, RopError> {
        if let Some(code) = source.failed {
            return Err(RopError::Code(code));
        }
        let limit = self
            .staged()
            .headroom()
            .saturating_sub(source.fixed_charge());
        let code_page = self.code_page().0;
        while source.encoder.buffered() < budget {
            let Some(unit) = source.unit(code_page) else {
                break;
            };
            let checkpoint = source.encoder.checkpoint();
            let (step, listed) = match unit {
                Unit::Message(message) => (
                    self.write_copy(source, &message, limit).await,
                    !source.items.is_message_root(),
                ),
                Unit::Attachment(attachment) => (
                    self.write_attachment_copy(source, &attachment, limit).await,
                    false,
                ),
                Unit::Folder(mark) => (
                    self.write_folder_mark(source, mark)
                        .await
                        .map(|()| Step::Written),
                    false,
                ),
            };
            let skipped = listed
                && match &step {
                    Err(RopError::Code(ErrorCode::NOT_FOUND | ErrorCode::OBJECT_DELETED)) => true,
                    Err(RopError::Code(_)) => source.recovery == Recovery::Skip,
                    _ => false,
                };
            if !matches!(step, Ok(Step::Written)) && !source.encoder.rollback(checkpoint) {
                return Err(RopError::Code(ErrorCode::ERROR));
            }
            match step {
                Ok(Step::Written) => source.cursor = source.cursor.saturating_add(1),
                Ok(Step::Deferred) => break,
                Err(_) if skipped => source.cursor = source.cursor.saturating_add(1),
                Err(err) => return Err(err),
            }
        }
        let total = source.total();
        Ok(Fill {
            finished: source.cursor >= total,
            in_progress: u16::try_from(source.cursor).unwrap_or(u16::MAX),
            total: u16::try_from(total).unwrap_or(u16::MAX),
        })
    }

    async fn write_copy(
        &mut self,
        source: &mut CopySource,
        message: &MessageObject,
        limit: u64,
    ) -> Result<Step, RopError> {
        let root = self.message_root(message).await?;
        let content = embedded(&root, &message.path).ok_or(ErrorCode::OBJECT_DELETED)?;
        let pending = source.encoder.buffered() > 0;
        if source.copies_attachments()
            && encoder_charge(&source.encoder).saturating_add(content_size(content)) > limit
        {
            return defer(pending);
        }
        let categories = self.category_source(message)?;
        let mailbox = self.mailbox(message.mailbox_id).await?;
        let bag = message_bag(message, content, &mailbox, categories);
        let guids = StoreGuids::new(mailbox.exchange.store_instance, message.mailbox_id);
        let versions = match source.identity {
            Identity::Send => self.copy_cn(&mailbox, message).map(|cn| {
                let client = self
                    .loaded_for(message)
                    .and_then(|loaded| loaded.client.as_ref());
                Versions::of(client, cn, guids.replica)
            }),
            Identity::Strip => None,
        };
        let names = AccountNamedProps::new(&mailbox.exchange);
        source.write(message, content, &bag, versions.as_ref(), &guids, &names)?;
        if encoder_charge(&source.encoder) > limit {
            return defer(pending);
        }
        Ok(Step::Written)
    }

    async fn write_attachment_copy(
        &mut self,
        source: &mut CopySource,
        attachment: &AttachmentObject,
        limit: u64,
    ) -> Result<Step, RopError> {
        let root = self.message_root(&attachment.message).await?;
        let item = embedded(&root, &attachment.message.path)
            .and_then(|content| attachment_at(content, attachment.number))
            .ok_or(ErrorCode::OBJECT_DELETED)?;
        let pending = source.encoder.buffered() > 0;
        let copies_data = source.filter.as_ref().is_none_or(|filter| {
            filter.allows(tags::ATTACH_DATA_BINARY) || filter.allows(tags::ATTACH_DATA_OBJECT)
        });
        if copies_data
            && encoder_charge(&source.encoder).saturating_add(attachment_size(item)) > limit
        {
            return defer(pending);
        }
        let mailbox = self.mailbox(attachment.message.mailbox_id).await?;
        let names = AccountNamedProps::new(&mailbox.exchange);
        write_attachment_content(&mut source.encoder, item, source.filter.as_ref(), &names, 0)?;
        if encoder_charge(&source.encoder) > limit {
            return defer(pending);
        }
        Ok(Step::Written)
    }

    pub(in crate::mapi::emsmdb) async fn push_versions(
        &mut self,
        message: &MessageObject,
        bag: &mut PropBag,
    ) -> Result<(), RopError> {
        let Some(id) = message.id().filter(|_| message.path.is_empty()) else {
            return Ok(());
        };
        let mailbox = self.mailbox(message.mailbox_id).await?;
        let guids = StoreGuids::new(mailbox.exchange.store_instance, message.mailbox_id);
        let versions = if id.space == IdSpace::Fai && message.staged.is_some() {
            self.fai_version(message, id.id)
                .await?
                .and_then(|(change, client)| {
                    ChangeSpace::Exchange
                        .cn(change)
                        .map(|cn| Versions::of(client.as_ref(), cn, guids.replica))
                })
        } else {
            match mailbox.stored_item(message.folder, id) {
                Some(stored) if stored.space == IdSpace::Email && message.staged.is_some() => {
                    match self.server_version(&mailbox, stored.id, &guids).await {
                        Ok(versions) => Some(versions),
                        Err(RopError::Code(ErrorCode::SYNC_OBJECT_DELETED)) => None,
                        Err(err) => return Err(err),
                    }
                }
                stored => {
                    let groupware = stored
                        .and_then(|stored| Some((stored.space.groupware()?, stored.id)))
                        .zip(self.item_change(message));
                    match (groupware, self.copy_cn(&mailbox, message)) {
                        (Some((item, change)), Some(cn)) => {
                            let client = self.groupware_client(&mailbox, item, change).await?;
                            Some(Versions::of(client.as_ref(), cn, guids.replica))
                        }
                        (_, cn) => cn.map(|cn| {
                            let client = self
                                .loaded_for(message)
                                .and_then(|loaded| loaded.client.as_ref());
                            Versions::of(client, cn, guids.replica)
                        }),
                    }
                }
            }
        };
        if let Some(versions) = versions {
            bag.push_binary(tags::CHANGE_KEY, &versions.change_key);
            bag.push_binary(tags::PREDECESSOR_CHANGE_LIST, &versions.pcl);
        }
        Ok(())
    }

    fn copy_cn(&mut self, mailbox: &MailboxView, message: &MessageObject) -> Option<ChangeNumber> {
        let id = message.id()?;
        if id.space == IdSpace::Fai {
            return self
                .loaded_for(message)
                .and_then(|loaded| ChangeSpace::Exchange.cn(loaded.origin));
        }
        let stored = mailbox.stored_item(message.folder, id)?;
        let groupware = match stored.space {
            IdSpace::Email => {
                return mailbox
                    .messages
                    .as_ref()
                    .and_then(|messages| messages.email_by_id(&stored.id))
                    .and_then(|item| ChangeSpace::Email.cn(item.change_id()));
            }
            IdSpace::Event => ChangeSpace::Calendar,
            IdSpace::Contact => ChangeSpace::AddressBook,
            _ => return None,
        };
        groupware.cn(self.item_change(message)?.max(1))
    }

    fn item_change(&mut self, message: &MessageObject) -> Option<u64> {
        match message.staged {
            Some(staged) => self.staged().message(staged)?.change,
            None => self.loaded_for(message)?.change,
        }
    }
}

fn write_identity(
    encoder: &mut FxEncoder,
    id: MapiId,
    bag: &PropBag,
    versions: Option<&Versions>,
    guids: &StoreGuids,
    names: &dyn NamedPropMap,
) -> Result<(), RopError> {
    let source_key = guids.gid(id.to_client_message()).to_wire();
    encoder
        .prop(tags::SOURCE_KEY, &PropValue::Binary(&source_key), names)
        .map_err(fx)?;
    if let Some(PropOut::Value(time @ PropValue::Time(_))) = bag.get(tags::LAST_MODIFICATION_TIME) {
        encoder
            .prop(tags::LAST_MODIFICATION_TIME, &time, names)
            .map_err(fx)?;
    }
    if let Some(versions) = versions {
        encoder
            .prop(
                tags::CHANGE_KEY,
                &PropValue::Binary(&versions.change_key),
                names,
            )
            .map_err(fx)?;
        encoder
            .prop(
                tags::PREDECESSOR_CHANGE_LIST,
                &PropValue::Binary(&versions.pcl),
                names,
            )
            .map_err(fx)?;
    }
    if let Some(PropOut::Value(entry_id @ PropValue::Binary(_))) = bag.get(tags::ENTRY_ID) {
        encoder
            .prop(tags::ORIGINAL_ENTRY_ID, &entry_id, names)
            .map_err(fx)?;
    }
    Ok(())
}

fn defer(pending: bool) -> Result<Step, RopError> {
    if pending {
        Ok(Step::Deferred)
    } else {
        Err(RopError::Code(ErrorCode::NOT_ENOUGH_MEMORY))
    }
}
