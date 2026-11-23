/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{
    COPY_FOLDER_FLAGS, CopyItems, CopySource, Identity, Recovery, STEP_CHARGE, Subobjects,
};
use crate::{
    folders::FolderNode,
    mapi::{
        emsmdb::{
            execute::{MailboxView, RopContext, RopError, RopResult},
            ics::{TagFilter, TransferContext, stream::fx},
            state::{FolderObject, ServerObject, TransferKind},
        },
        ids::{IdSpace, MapiId},
    },
    store::{FolderKind, FolderRef, folder::FolderStore, named::AccountNamedProps},
};
use email::cache::email::MessageCacheAccess;
use exchange_proto::{
    ics::{
        flags::FastTransferCopyFlags,
        fx::{FxEncoder, Marker, tags as subobject},
    },
    mapi::{
        ErrorCode,
        prop::{PropTag, PropValue, tags},
        rop::{DecodedRop, requests::FastTransferSourceCopyFolder},
    },
};
use trc::AddContext;
use types::type_state::DataType;

const MIN_PLAN_GROWTH: usize = 64;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum FolderStep {
    Folder(FolderMark),
    Message { folder: u64, message: u64 },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum FolderMark {
    Root(u64),
    Top(u64),
    Sub(u64),
    Delete(PropTag),
    End,
}

pub(super) enum FolderRoot {
    Content {
        filter: TagFilter,
        subobjects: Subobjects,
    },
    Top(Subobjects),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DelProps {
    Write,
    Omit,
}

struct FolderPlan {
    steps: Vec<FolderStep>,
    capacity: usize,
    deletes: DelProps,
    full: bool,
}

impl FolderPlan {
    fn push(&mut self, step: FolderStep) -> bool {
        let len = self.steps.len();
        if len >= self.capacity {
            self.full = true;
            return false;
        }
        if len == self.steps.capacity() {
            self.steps
                .reserve_exact(len.max(MIN_PLAN_GROWTH).min(self.capacity - len));
        }
        self.steps.push(step);
        true
    }

    fn mark(&mut self, mark: FolderMark) -> bool {
        self.push(FolderStep::Folder(mark))
    }

    fn delete(&mut self, tag: PropTag) {
        if self.deletes == DelProps::Write {
            self.mark(FolderMark::Delete(tag));
        }
    }
}

impl FolderRoot {
    fn includes(&self, tag: PropTag) -> bool {
        match self {
            FolderRoot::Content { filter, subobjects } => {
                *subobjects == Subobjects::Copy && filter.allows(tag)
            }
            FolderRoot::Top(subfolders) => {
                tag != subobject::CONTAINER_HIERARCHY || *subfolders == Subobjects::Copy
            }
        }
    }
}

impl RopContext<'_, '_> {
    pub async fn fast_transfer_source_copy_folder(
        &mut self,
        rop: &DecodedRop<'_>,
        request: &FastTransferSourceCopyFolder,
    ) -> RopResult {
        let flags = request.copy_flags;
        if flags.0 & !COPY_FOLDER_FLAGS != 0 || flags.contains(FastTransferCopyFlags::MOVE) {
            return Err(RopError::Code(ErrorCode::INVALID_PARAM));
        }
        let encoder = self.copy_encoder(request.send_options)?;
        let parent = self.input(rop.header.input_handle)?;
        let folder = match self.state.get(parent) {
            Some(ServerObject::Folder(folder)) => *folder,
            Some(_) => return Err(RopError::Code(ErrorCode::NOT_SUPPORTED)),
            None => return Err(RopError::Code(ErrorCode::NULL_OBJECT)),
        };
        let subfolders = if flags.contains(FastTransferCopyFlags::COPY_SUBFOLDERS) {
            Subobjects::Copy
        } else {
            Subobjects::Skip
        };
        self.open_folder_source(
            rop,
            request.output_handle_index,
            folder,
            FolderRoot::Top(subfolders),
            Recovery::of(request.send_options),
            encoder,
        )
        .await
    }

    pub(super) async fn open_folder_source(
        &mut self,
        rop: &DecodedRop<'_>,
        index: u8,
        folder: FolderObject,
        root: FolderRoot,
        recovery: Recovery,
        encoder: FxEncoder,
    ) -> RopResult {
        let parent = self.input(rop.header.input_handle)?;
        if !self.types.contains(DataType::Email) {
            return Err(RopError::Code(ErrorCode::ACCESS_DENIED));
        }
        let steps = self.folder_plan(folder, &root).await?;
        let filter = match root {
            FolderRoot::Content { filter, .. } => Some(filter),
            FolderRoot::Top(_) => None,
        };
        let source = CopySource {
            items: CopyItems::Folder {
                mailbox_id: folder.mailbox_id,
                steps,
            },
            filter,
            subobjects: Subobjects::Copy,
            identity: Identity::Strip,
            recovery,
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

    async fn folder_plan(
        &mut self,
        folder: FolderObject,
        root: &FolderRoot,
    ) -> Result<Box<[FolderStep]>, RopError> {
        let mailbox_id = folder.mailbox_id;
        let node = folder
            .id()
            .and_then(MapiId::to_node)
            .ok_or(ErrorCode::OBJECT_DELETED)?;
        let tree = self.folder_tree(mailbox_id).await?;
        if tree.get(node).is_none() {
            return Err(RopError::Code(ErrorCode::OBJECT_DELETED));
        }
        let mailbox = self.mailbox(mailbox_id).await?;
        let rights = self.view_rights(mailbox_id).await?;
        let root_rights = rights.of(node);
        if !root_rights.is_visible() {
            return Err(RopError::Code(ErrorCode::NOT_FOUND));
        }
        let reads = root_rights.reads_items();
        let mut plan = FolderPlan {
            steps: Vec::new(),
            capacity: usize::try_from(self.staged().headroom() / STEP_CHARGE).unwrap_or(usize::MAX),
            deletes: match root {
                FolderRoot::Content { .. } => DelProps::Write,
                FolderRoot::Top(_) => DelProps::Omit,
            },
            full: false,
        };
        plan.mark(match root {
            FolderRoot::Content { .. } => FolderMark::Root(folder.counter),
            FolderRoot::Top(_) => FolderMark::Top(folder.counter),
        });
        self.plan_messages(
            &mut plan,
            &mailbox,
            node,
            folder.counter,
            [
                root.includes(subobject::CONTAINER_CONTENTS),
                root.includes(subobject::FOLDER_ASSOCIATED_CONTENTS),
            ]
            .map(|included| included && reads),
        )
        .await?;
        if root.includes(subobject::CONTAINER_HIERARCHY) && !plan.full {
            plan.delete(subobject::CONTAINER_HIERARCHY);
            let mut levels = vec![tree.children(node)];
            while let Some(level) = levels.last_mut() {
                match level.next() {
                    Some(child) => {
                        let child_rights = rights.of(child.node);
                        if !child_rights.is_visible() {
                            continue;
                        }
                        let counter = MapiId::from_node(child.node).counter();
                        plan.mark(FolderMark::Sub(counter));
                        self.plan_messages(
                            &mut plan,
                            &mailbox,
                            child.node,
                            counter,
                            [child_rights.reads_items(); 2],
                        )
                        .await?;
                        plan.delete(subobject::CONTAINER_HIERARCHY);
                        levels.push(tree.children(child.node));
                    }
                    None => {
                        levels.pop();
                        if !levels.is_empty() {
                            plan.mark(FolderMark::End);
                        }
                    }
                }
                if plan.full {
                    break;
                }
            }
        }
        if matches!(root, FolderRoot::Top(_)) {
            plan.mark(FolderMark::End);
        }
        if plan.full {
            return Err(RopError::Code(ErrorCode::NOT_ENOUGH_MEMORY));
        }
        Ok(plan.steps.into_boxed_slice())
    }

    async fn plan_messages(
        &mut self,
        plan: &mut FolderPlan,
        mailbox: &MailboxView,
        node: FolderNode,
        folder: u64,
        [normal, associated]: [bool; 2],
    ) -> Result<(), RopError> {
        if normal
            && let (
                FolderNode::Stored(FolderRef {
                    kind: FolderKind::Mailbox,
                    id: container,
                }),
                Some(messages),
            ) = (node, mailbox.messages.as_ref())
        {
            plan.delete(subobject::CONTAINER_CONTENTS);
            for item in messages.in_mailbox(container) {
                let id = MapiId::new(
                    IdSpace::Email,
                    mailbox.email_item(container, item.document_id()),
                );
                if !plan.push(FolderStep::Message {
                    folder,
                    message: id.counter(),
                }) {
                    return Ok(());
                }
            }
        }
        if associated && let Ok(fai_folder) = self.fai_folder(mailbox.id, node) {
            plan.delete(subobject::FOLDER_ASSOCIATED_CONTENTS);
            self.request
                .server
                .fai_messages(mailbox.id, fai_folder, |id, _| {
                    Ok(plan.push(FolderStep::Message {
                        folder,
                        message: MapiId::new(IdSpace::Fai, id).counter(),
                    }))
                })
                .await
                .caused_by(trc::location!())?;
        }
        Ok(())
    }

    pub(super) async fn write_folder_mark(
        &mut self,
        source: &mut CopySource,
        mark: FolderMark,
    ) -> Result<(), RopError> {
        let (counter, marker) = match mark {
            FolderMark::Delete(tag) => return source.encoder.fx_del_prop(tag).map_err(fx),
            FolderMark::End => return source.encoder.marker(Marker::EndFolder).map_err(fx),
            FolderMark::Root(counter) => (counter, None),
            FolderMark::Top(counter) => (counter, Some(Marker::StartTopFld)),
            FolderMark::Sub(counter) => (counter, Some(Marker::StartSubFld)),
        };
        let CopyItems::Folder { mailbox_id, .. } = source.items else {
            return Err(RopError::Code(ErrorCode::ERROR));
        };
        let node = MapiId::from_counter(counter)
            .and_then(MapiId::to_node)
            .ok_or(ErrorCode::OBJECT_DELETED)?;
        let tree = self.folder_tree(mailbox_id).await?;
        let entry = tree.get(node).ok_or(ErrorCode::OBJECT_DELETED)?;
        let mailbox = self.mailbox(mailbox_id).await?;
        let names = AccountNamedProps::new(&mailbox.exchange);
        let filter = match mark {
            FolderMark::Root(_) => source.filter.as_ref(),
            _ => None,
        };
        let allowed = |tag: PropTag| filter.is_none_or(|filter| filter.allows(tag));
        let access = if matches!(filter, Some(TagFilter::Include(_))) && allowed(tags::ACCESS) {
            Some(self.view_rights(mailbox_id).await?.of(node).access())
        } else {
            None
        };
        let encoder = &mut source.encoder;
        if let Some(marker) = marker {
            encoder.marker(marker).map_err(fx)?;
        }
        if marker != Some(Marker::StartTopFld) && allowed(tags::FOLDER_ID) {
            let fid = MapiId::from_folder(&mailbox.exchange, node).to_eid();
            encoder
                .prop(
                    tags::FOLDER_ID,
                    &PropValue::I64(i64::from_le_bytes(fid.to_wire())),
                    &names,
                )
                .map_err(fx)?;
        }
        if allowed(tags::DISPLAY_NAME) {
            encoder
                .prop_text(tags::DISPLAY_NAME, &entry.name, &names)
                .map_err(fx)?;
        }
        if marker != Some(Marker::StartTopFld) && allowed(tags::COMMENT) {
            encoder.prop_text(tags::COMMENT, "", &names).map_err(fx)?;
        }
        let class = entry.class.as_str();
        if !class.is_empty() && allowed(tags::CONTAINER_CLASS) {
            encoder
                .prop_text(tags::CONTAINER_CLASS, class, &names)
                .map_err(fx)?;
        }
        if let Some(access) = access {
            encoder
                .prop(tags::ACCESS, &PropValue::I32(access), &names)
                .map_err(fx)?;
        }
        Ok(())
    }
}
