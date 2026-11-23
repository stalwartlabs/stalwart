/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{CONTEXT_BASE_CHARGE, TransferContext};
use crate::{
    folders::{ContainerClass, FolderNode},
    mail::AccountCategories,
    mapi::{
        emsmdb::{
            access::ItemWrite,
            execute::{RopContext, RopError, RopResult},
            folder_write::OpenFolder,
            message::save::MailContainer,
            staged::StagedObject,
            state::{AttachmentObject, MessageObject, ServerObject, TransferKind, mail_container},
        },
        ids::MapiId,
        text::decode_text,
    },
    store::{FolderKind, FolderRef, object::ObjectVersion},
};
use common::cache::exchange::CategoryTable;
use exchange_proto::{
    convert::model::{MessageContent, PropBag},
    ics::{
        IcsLimits,
        flags::{DestinationCopyFlags, SourceOperation, TransferStatus},
        fx::{CopyBuilder, CopyItem, CopyRoot, FxDecoder},
    },
    mapi::{
        ErrorCode,
        prop::{CodePage, OwnedPropValue, PropId, PropKeyRef, PropValue, tags},
        rop::{
            DecodedRop,
            requests::{FastTransferDestinationConfigure, FastTransferDestinationPutBuffer},
            responses::{
                FastTransferDestinationPutBufferExtendedResponse,
                FastTransferDestinationPutBufferResponse,
            },
        },
    },
};
use smallvec::SmallVec;
use std::{borrow::Cow, sync::Arc};
use types::type_state::DataType;

pub struct UploadContext {
    decoder: FxDecoder,
    builder: CopyBuilder,
    target: UploadTarget,
    categories: Arc<CategoryTable>,
    failed: Option<ErrorCode>,
}

enum UploadTarget {
    Folder(FolderTarget),
    Message(MessageObject),
    Attachment(AttachmentObject),
}

struct FolderTarget {
    mailbox_id: u32,
    store_instance: u64,
    folders: SmallVec<[FolderNode; 4]>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PutBufferForm {
    Standard,
    Extended,
}

impl UploadContext {
    pub(super) fn charge(&self) -> u64 {
        CONTEXT_BASE_CHARGE
            .saturating_add(u64::try_from(self.builder.heap_size()).unwrap_or(u64::MAX))
    }

    pub(super) fn fail(&mut self, code: ErrorCode) {
        if self.failed.is_none() {
            self.failed = Some(code);
        }
        self.builder = CopyBuilder::new(self.builder.root());
    }

    fn status(&self) -> TransferStatus {
        if self.builder.is_idle() && self.decoder.depth() == 0 {
            TransferStatus::Done
        } else {
            TransferStatus::Partial
        }
    }

    fn decode(&mut self, data: &[u8], cap: u64, items: &mut Vec<CopyItem>) -> Option<ErrorCode> {
        let mut events = self.decoder.feed(data);
        loop {
            match events.next() {
                Ok(Some(event)) => {
                    if let Err(err) = self.builder.push(event, items) {
                        return Some(err.error_code());
                    }
                    if u64::try_from(self.builder.heap_size()).unwrap_or(u64::MAX) > cap {
                        return Some(ErrorCode::TOO_BIG);
                    }
                }
                Ok(None) => return None,
                Err(err) => return Some(err.error_code()),
            }
        }
    }
}

impl FolderTarget {
    fn current(&self) -> Result<FolderNode, RopError> {
        self.folders
            .last()
            .copied()
            .ok_or(RopError::Code(ErrorCode::RPC_FORMAT))
    }

    fn container(&self) -> Result<MailContainer, RopError> {
        match self.current()? {
            FolderNode::Stored(FolderRef {
                kind: FolderKind::Mailbox,
                id,
            }) => Ok(MailContainer {
                mailbox_id: self.mailbox_id,
                container: id,
                store_instance: self.store_instance,
            }),
            _ => Err(RopError::Code(ErrorCode::NOT_SUPPORTED)),
        }
    }

    fn open(&self) -> Result<OpenFolder, RopError> {
        Ok(OpenFolder {
            mailbox_id: self.mailbox_id,
            node: self.current()?,
        })
    }
}

impl RopContext<'_, '_> {
    pub async fn fast_transfer_destination_configure(
        &mut self,
        rop: &DecodedRop<'_>,
        request: &FastTransferDestinationConfigure,
    ) -> RopResult {
        let parent = self.input(rop.header.input_handle)?;
        let operation = SourceOperation::from_wire(request.source_operation)
            .ok_or(RopError::Code(ErrorCode::INVALID_PARAM))?;
        let flags = DestinationCopyFlags(request.copy_flags);
        if flags.0 & !DestinationCopyFlags::MOVE != 0 {
            return Err(RopError::Code(ErrorCode::INVALID_PARAM));
        }
        let content_copy = matches!(
            operation,
            SourceOperation::CopyTo | SourceOperation::CopyProperties
        );
        let (root, folder, target) = match self.state.get(parent) {
            Some(ServerObject::Folder(folder)) => {
                let folder = *folder;
                let root = match operation {
                    SourceOperation::CopyTo | SourceOperation::CopyProperties => {
                        CopyRoot::FolderContent
                    }
                    SourceOperation::CopyMessages => CopyRoot::MessageList,
                    SourceOperation::CopyFolder => CopyRoot::TopFolder,
                };
                if !self.types.contains(DataType::Email) {
                    return Err(RopError::Code(ErrorCode::ACCESS_DENIED));
                }
                if root != CopyRoot::TopFolder && mail_container(folder.counter).is_none() {
                    return Err(RopError::Code(ErrorCode::NOT_SUPPORTED));
                }
                let node = folder
                    .id()
                    .and_then(MapiId::to_node)
                    .ok_or(ErrorCode::OBJECT_DELETED)?;
                let store_instance = self
                    .mailbox(folder.mailbox_id)
                    .await?
                    .exchange
                    .store_instance;
                let target = UploadTarget::Folder(FolderTarget {
                    mailbox_id: folder.mailbox_id,
                    store_instance,
                    folders: SmallVec::from_elem(node, 1),
                });
                (root, folder, target)
            }
            Some(ServerObject::Attachment(_)) if flags.contains(DestinationCopyFlags::MOVE) => {
                return Err(RopError::Code(ErrorCode::INVALID_PARAM));
            }
            Some(ServerObject::Message(_) | ServerObject::Attachment(_)) if content_copy => {
                let attachment = match self.state.get(parent) {
                    Some(ServerObject::Attachment(attachment)) => Some(attachment.number),
                    _ => None,
                };
                if !self.types.contains(DataType::Email) {
                    return Err(RopError::Code(ErrorCode::ACCESS_DENIED));
                }
                let message = self.stage_handle(parent).await?;
                if self.staged_message(&message)?.associated {
                    return Err(RopError::Code(ErrorCode::NOT_SUPPORTED));
                }
                let folder = message.folder();
                let (root, target) = match attachment {
                    Some(number) => (
                        CopyRoot::AttachmentContent,
                        UploadTarget::Attachment(AttachmentObject { message, number }),
                    ),
                    None => (CopyRoot::MessageContent, UploadTarget::Message(message)),
                };
                (root, folder, target)
            }
            Some(_) => return Err(RopError::Code(ErrorCode::NOT_SUPPORTED)),
            None => return Err(RopError::Code(ErrorCode::NULL_OBJECT)),
        };
        let categories = self
            .mailbox(folder.mailbox_id)
            .await?
            .exchange
            .categories
            .clone();
        let context = TransferContext::Upload(Box::new(UploadContext {
            decoder: FxDecoder::new(&IcsLimits::DEFAULT),
            builder: CopyBuilder::new(root),
            target,
            categories,
            failed: None,
        }));
        self.open_transfer(
            rop,
            parent,
            request.output_handle_index,
            folder,
            TransferKind::Upload,
            context,
        )
    }

    pub async fn fast_transfer_destination_put_buffer(
        &mut self,
        rop: &DecodedRop<'_>,
        request: &FastTransferDestinationPutBuffer<'_>,
        form: PutBufferForm,
    ) -> RopResult {
        let transfer = self.transfer_object(rop)?;
        let used = u16::try_from(request.transfer_data.len())
            .map_err(|_| RopError::Code(ErrorCode::INVALID_PARAM))?;
        let Some(StagedObject::Transfer(mut context)) = self.staged().remove(transfer.staged)
        else {
            return Err(RopError::Code(ErrorCode::NULL_OBJECT));
        };
        let outcome = match context.as_mut() {
            TransferContext::Upload(upload) => self
                .put_upload(upload, request.transfer_data)
                .await
                .map(|()| upload.status()),
            TransferContext::Sync(_) | TransferContext::Buffer(_) | TransferContext::Copy(_) => {
                Err(RopError::Code(ErrorCode::NOT_SUPPORTED))
            }
        };
        let charge = context.charge();
        self.staged()
            .insert(transfer.staged, StagedObject::Transfer(context), charge)?;
        let transfer_status = outcome?;
        match form {
            PutBufferForm::Standard => self.respond(
                rop,
                rop.header.handle_index,
                &FastTransferDestinationPutBufferResponse {
                    transfer_status,
                    in_progress_count: 0,
                    total_step_count: 0,
                    buffer_used_size: used,
                },
            ),
            PutBufferForm::Extended => self.respond(
                rop,
                rop.header.handle_index,
                &FastTransferDestinationPutBufferExtendedResponse {
                    transfer_status,
                    in_progress_count: 0,
                    total_step_count: 0,
                    buffer_used_size: used,
                },
            ),
        }
    }

    async fn put_upload(&mut self, upload: &mut UploadContext, data: &[u8]) -> RopResult {
        if let Some(code) = upload.failed {
            return Err(RopError::Code(code));
        }
        let result = self.feed_upload(upload, data).await;
        if let Err(err) = &result {
            upload.fail(match err {
                RopError::Code(code) => *code,
                RopError::Overflow | RopError::Internal(_) => ErrorCode::ERROR,
            });
        }
        result
    }

    async fn feed_upload(&mut self, upload: &mut UploadContext, data: &[u8]) -> RopResult {
        if !self.types.contains(DataType::Email) {
            return Err(RopError::Code(ErrorCode::ACCESS_DENIED));
        }
        let added = u64::try_from(data.len()).unwrap_or(u64::MAX);
        let charge = upload.charge().saturating_add(added);
        let cap = self.staged().message_cap();
        self.staged().reserve_for(charge)?;
        let mut items = Vec::new();
        let decode_error = upload.decode(data, cap, &mut items);
        match &mut upload.target {
            UploadTarget::Folder(target) => {
                let committed = !items.is_empty();
                let result = self
                    .copy_into_folder(target, &mut upload.categories, items)
                    .await;
                if committed {
                    self.invalidate_mailbox();
                }
                result?;
            }
            UploadTarget::Message(message) => self.copy_items(message, None, items)?,
            UploadTarget::Attachment(attachment) => {
                self.copy_items(&attachment.message, Some(attachment.number), items)?
            }
        }
        match decode_error {
            Some(code) => Err(RopError::Code(code)),
            None => Ok(()),
        }
    }

    async fn copy_into_folder(
        &mut self,
        target: &mut FolderTarget,
        categories: &mut Arc<CategoryTable>,
        items: Vec<CopyItem>,
    ) -> RopResult {
        let code_page = self.code_page();
        for item in items {
            match item {
                CopyItem::Prop(..) => {}
                CopyItem::FolderStart(props) => {
                    let name = folder_text(&props, tags::DISPLAY_NAME.id(), code_page);
                    let class = folder_text(&props, tags::CONTAINER_CLASS.id(), code_page)
                        .filter(|class| !class.is_empty())
                        .map(|class| ContainerClass::parse(&class));
                    let created = self
                        .create_child_folder(
                            target.open()?,
                            name.as_deref().unwrap_or_default(),
                            class.as_ref(),
                            None,
                        )
                        .await?;
                    self.invalidate_mailbox();
                    target.folders.push(FolderNode::Stored(created?));
                }
                CopyItem::FolderEnd if target.folders.len() > 1 => {
                    target.folders.pop();
                }
                CopyItem::Message(message) => {
                    self.require_node_write(
                        target.mailbox_id,
                        target.current()?,
                        ItemWrite::Create,
                    )
                    .await?;
                    self.copy_message(target.container()?, categories, &message)
                        .await?;
                }
                CopyItem::FaiMessage(message) => {
                    self.require_node_write(
                        target.mailbox_id,
                        target.current()?,
                        ItemWrite::Associated,
                    )
                    .await?;
                    let folder = self.fai_folder(target.mailbox_id, target.current()?)?;
                    self.create_fai_content(target.mailbox_id, folder, &message)
                        .await?;
                }
                _ => return Err(RopError::Code(ErrorCode::RPC_FORMAT)),
            }
        }
        Ok(())
    }

    async fn copy_message(
        &mut self,
        container: MailContainer,
        categories: &mut Arc<CategoryTable>,
        message: &MessageContent,
    ) -> RopResult {
        let created = self
            .create_mail_content(
                message,
                container,
                AccountCategories::from_table(categories),
                ObjectVersion::Server,
                None,
            )
            .await?;
        if created.respelled {
            self.invalidate_mailbox();
            *categories = self
                .mailbox(container.mailbox_id)
                .await?
                .exchange
                .categories
                .clone();
        }
        Ok(())
    }
}

fn folder_text(props: &PropBag, id: PropId, code_page: CodePage) -> Option<Cow<'_, str>> {
    props
        .get_any(PropKeyRef::Tag(id))
        .and_then(|value| text(value, code_page))
}

fn text(value: &OwnedPropValue, code_page: CodePage) -> Option<Cow<'_, str>> {
    match value {
        OwnedPropValue::Unicode(unicode) => Some(Cow::Borrowed(unicode.as_ref())),
        OwnedPropValue::String8(bytes) => {
            let mut out = String::new();
            decode_text(&PropValue::String8(bytes), code_page, &mut out).then_some(Cow::Owned(out))
        }
        _ => None,
    }
}
