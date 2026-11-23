/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{
    execute::{RopContext, RopError, RopResult},
    folder_store::{RowEdit, is_folder_computed},
    folder_write::OpenFolder,
    message::{attachment_at, load::embedded, object_row::decode_property},
    state::{Handle, MessageObject, ServerObject},
};
use crate::store::{named::AccountNamedProps, object::ExchangeObject};
use exchange_proto::{
    convert::model::{AttachData, MessageContent, PropBag as ContentBag},
    ics::fx::{Children, CopyItem, tags as subobject},
    mapi::{
        ErrorCode,
        prop::{NamedPropMap, OwnedPropValue, PropId, PropKey, PropKeyRef, PropTag, tags},
        rop::{
            DecodedRop,
            requests::{CopyProperties, CopyTo},
            responses::{PropertyProblem, SetPropertiesResponse},
            views::PropTagArrayView,
        },
    },
};
use smallvec::SmallVec;

const COPY_MOVE: u8 = 0x01;
const COPY_NO_OVERWRITE: u8 = 0x02;
const COPY_VALID: u8 = COPY_MOVE | COPY_NO_OVERWRITE;

type Problems = SmallVec<[PropertyProblem; 8]>;

enum Selection {
    Only(SmallVec<[PropTag; 16]>),
    Except(SmallVec<[PropId; 16]>),
}

impl Selection {
    fn only(tags: PropTagArrayView<'_>) -> Self {
        Selection::Only(tags.iter().collect())
    }

    fn except(tags: PropTagArrayView<'_>) -> Self {
        Selection::Except(tags.iter().map(PropTag::id).collect())
    }

    fn allows(&self, id: PropId) -> bool {
        match self {
            Selection::Only(tags) => tags.iter().any(|tag| tag.id() == id),
            Selection::Except(ids) => !ids.contains(&id),
        }
    }

    fn allows_key(&self, id: Option<PropId>) -> bool {
        match id {
            Some(id) => self.allows(id),
            None => matches!(self, Selection::Except(_)),
        }
    }

    fn missing(&self, found: &[PropId], problems: &mut Problems) {
        if let Selection::Only(tags) = self {
            problems.extend(
                tags.iter()
                    .enumerate()
                    .filter(|(_, tag)| {
                        !found.contains(&tag.id())
                            && tag.id() != subobject::MESSAGE_RECIPIENTS.id()
                            && tag.id() != subobject::MESSAGE_ATTACHMENTS.id()
                    })
                    .map(|(position, tag)| PropertyProblem {
                        index: u16::try_from(position).unwrap_or(u16::MAX),
                        tag: *tag,
                        error: ErrorCode::NOT_FOUND,
                    }),
            );
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Overwrite {
    Replace,
    Keep,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum SubObjects {
    Copy,
    Skip,
}

struct CopyRequest {
    dest_handle_index: u8,
    flags: u8,
    sub_objects: SubObjects,
    selection: Selection,
    kind: CopyKind,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum CopyKind {
    Properties,
    To,
}

enum Endpoint {
    Folder(OpenFolder),
    Message(MessageObject),
    Attachment(MessageObject, u32),
}

impl RopContext<'_, '_> {
    pub async fn copy_properties(
        &mut self,
        rop: &DecodedRop<'_>,
        index: u8,
        request: &CopyProperties<'_>,
    ) -> RopResult {
        self.copy_objects(
            rop,
            index,
            CopyRequest {
                dest_handle_index: request.dest_handle_index,
                flags: request.copy_flags,
                sub_objects: SubObjects::Copy,
                selection: Selection::only(request.property_tags),
                kind: CopyKind::Properties,
            },
        )
        .await
    }

    pub async fn copy_to(
        &mut self,
        rop: &DecodedRop<'_>,
        index: u8,
        request: &CopyTo<'_>,
    ) -> RopResult {
        self.copy_objects(
            rop,
            index,
            CopyRequest {
                dest_handle_index: request.dest_handle_index,
                flags: request.copy_flags,
                sub_objects: if request.want_sub_objects {
                    SubObjects::Copy
                } else {
                    SubObjects::Skip
                },
                selection: Selection::except(request.excluded_tags),
                kind: CopyKind::To,
            },
        )
        .await
    }

    async fn copy_objects(
        &mut self,
        rop: &DecodedRop<'_>,
        index: u8,
        request: CopyRequest,
    ) -> RopResult {
        if request.flags & !COPY_VALID != 0 || request.flags == COPY_VALID {
            return Err(RopError::Code(ErrorCode::INVALID_PARAM));
        }
        let source = self.copy_endpoint(self.input(rop.header.input_handle)?)?;
        let dest_handle = self
            .input(request.dest_handle_index)
            .map_err(|_| ErrorCode::DST_NULL_OBJECT)?;
        let dest = self.copy_endpoint(dest_handle)?;
        let overwrite = if request.flags & COPY_NO_OVERWRITE != 0 {
            Overwrite::Keep
        } else {
            Overwrite::Replace
        };
        let mut problems = Problems::new();
        match (source, dest) {
            (Endpoint::Folder(source), Endpoint::Folder(dest)) => {
                if request.kind == CopyKind::Properties && request.flags & COPY_MOVE != 0 {
                    return Err(RopError::Code(ErrorCode::NOT_SUPPORTED));
                }
                if request.sub_objects == SubObjects::Copy && request.kind == CopyKind::To {
                    self.check_folder_copy(source, dest).await?;
                }
                self.copy_folder_row(source, dest, &request.selection, overwrite, &mut problems)
                    .await?;
            }
            (Endpoint::Message(source), Endpoint::Message(dest)) => {
                if source.same_root(&dest)
                    && dest.path.len() > source.path.len()
                    && dest.path.starts_with(&source.path)
                {
                    return Err(RopError::Code(ErrorCode::MSG_CYCLE));
                }
                let root = self.message_root(&source).await?;
                let content = embedded(&root, &source.path).ok_or(ErrorCode::OBJECT_DELETED)?;
                let names = self.mailbox(source.mailbox_id).await?.exchange;
                let names = AccountNamedProps::new(&names);
                let mut found = SmallVec::<[PropId; 16]>::new();
                let mut items = Vec::new();
                select_props(
                    &content.props,
                    &request.selection,
                    &names,
                    &mut found,
                    &mut items,
                );
                request.selection.missing(&found, &mut problems);
                let dest_message = self.stage_handle(dest_handle).await?;
                let dest_root = self
                    .staged_message(&dest_message)?
                    .content_at(&dest_message.path)?;
                retain_new(&mut items, &dest_root.props, overwrite);
                if request.sub_objects == SubObjects::Copy {
                    push_children(
                        content,
                        dest_root,
                        &request.selection,
                        overwrite,
                        &mut items,
                    );
                }
                self.copy_items(&dest_message, None, items)?;
            }
            (Endpoint::Attachment(source, number), Endpoint::Attachment(_, dest_number)) => {
                let root = self.message_root(&source).await?;
                let item = embedded(&root, &source.path)
                    .and_then(|content| attachment_at(content, number))
                    .ok_or(ErrorCode::OBJECT_DELETED)?;
                let names = self.mailbox(source.mailbox_id).await?.exchange;
                let names = AccountNamedProps::new(&names);
                let mut found = SmallVec::<[PropId; 16]>::new();
                let mut items = Vec::new();
                select_props(
                    &item.props,
                    &request.selection,
                    &names,
                    &mut found,
                    &mut items,
                );
                let dest_message = self.stage_handle(dest_handle).await?;
                let dest_item = attachment_at(
                    self.staged_message(&dest_message)?
                        .content_at(&dest_message.path)?,
                    dest_number,
                )
                .ok_or(ErrorCode::OBJECT_DELETED)?;
                retain_new(&mut items, &dest_item.props, overwrite);
                let dest_has_data = !matches!(dest_item.data, AttachData::None);
                if overwrite == Overwrite::Replace || !dest_has_data {
                    match &item.data {
                        AttachData::Bytes(bytes)
                            if request.selection.allows(tags::ATTACH_DATA_BINARY.id()) =>
                        {
                            found.push(tags::ATTACH_DATA_BINARY.id());
                            items.push(CopyItem::Prop(
                                PropKey::tag(tags::ATTACH_DATA_BINARY.id()),
                                OwnedPropValue::Binary(bytes.clone()),
                            ));
                        }
                        AttachData::Embedded(content)
                            if request.sub_objects == SubObjects::Copy
                                && request.selection.allows(tags::ATTACH_DATA_OBJECT.id()) =>
                        {
                            found.push(tags::ATTACH_DATA_OBJECT.id());
                            items.push(CopyItem::Embedded(content.as_ref().clone()));
                        }
                        _ => {}
                    }
                }
                request.selection.missing(&found, &mut problems);
                self.copy_items(&dest_message, Some(dest_number), items)?;
            }
            _ => return Err(RopError::Code(ErrorCode::NOT_SUPPORTED)),
        }
        self.respond(
            rop,
            index,
            &SetPropertiesResponse {
                property_problems: &problems,
            },
        )
    }

    fn copy_endpoint(&self, handle: Handle) -> Result<Endpoint, RopError> {
        match self.state.get(handle) {
            Some(ServerObject::Folder(_)) => self.open_folder_at(handle).map(Endpoint::Folder),
            Some(ServerObject::Message(message)) => {
                Ok(Endpoint::Message(message.without_columns()))
            }
            Some(ServerObject::Attachment(attachment)) => Ok(Endpoint::Attachment(
                attachment.message.clone(),
                attachment.number,
            )),
            Some(_) => Err(RopError::Code(ErrorCode::NOT_SUPPORTED)),
            None => Err(RopError::Code(ErrorCode::NULL_OBJECT)),
        }
    }

    async fn check_folder_copy(&mut self, source: OpenFolder, dest: OpenFolder) -> RopResult {
        let tree = self.folder_tree(source.mailbox_id).await?;
        let dest_tree = if source.mailbox_id == dest.mailbox_id {
            if tree.in_subtree(source.node, dest.node) {
                return Err(RopError::Code(ErrorCode::FOLDER_CYCLE));
            }
            tree.clone()
        } else {
            self.folder_tree(dest.mailbox_id).await?
        };
        if tree.children(source.node).any(|child| {
            dest_tree
                .children(dest.node)
                .any(|existing| existing.name.eq_ignore_ascii_case(&child.name))
        }) {
            return Err(RopError::Code(ErrorCode::DUPLICATE_NAME));
        }
        Ok(())
    }

    async fn copy_folder_row(
        &mut self,
        source: OpenFolder,
        dest: OpenFolder,
        selection: &Selection,
        overwrite: Overwrite,
        problems: &mut Problems,
    ) -> RopResult {
        let names = self.mailbox(source.mailbox_id).await?.exchange;
        let names = AccountNamedProps::new(&names);
        let mut found = SmallVec::<[PropId; 16]>::new();
        let mut edits = SmallVec::<[RowEdit; 8]>::new();
        if let Some(row) = self.folder_row(source.mailbox_id, source.node).await? {
            for property in row.unarchive::<ExchangeObject>()?.properties.iter() {
                let Some((key, value)) =
                    decode_property(property.key.as_slice(), property.value.as_slice())
                else {
                    continue;
                };
                let id = key_id(&key, &names);
                if id.is_some_and(|id| {
                    id == tags::CONTAINER_CLASS.id()
                        || is_folder_computed(PropTag::new(id, value.ptype()))
                }) || !selection.allows_key(id)
                {
                    continue;
                }
                if let Some(id) = id {
                    found.push(id);
                }
                let (key, value) = (property.key.to_vec(), property.value.to_vec());
                edits.push(match overwrite {
                    Overwrite::Keep => RowEdit::SetIfAbsent(key, value),
                    Overwrite::Replace => RowEdit::Set(key, value),
                });
            }
        }
        selection.missing(&found, problems);
        if !edits.is_empty() {
            self.edit_owned_folder_row(dest, &edits).await?;
        }
        Ok(())
    }
}

fn key_id(key: &PropKey, names: &AccountNamedProps<'_>) -> Option<PropId> {
    match key.as_ref() {
        PropKeyRef::Tag(id) => Some(id),
        key => names.id(key),
    }
}

fn select_props(
    props: &ContentBag,
    selection: &Selection,
    names: &AccountNamedProps<'_>,
    found: &mut SmallVec<[PropId; 16]>,
    items: &mut Vec<CopyItem>,
) {
    for (key, value) in props.iter() {
        let id = key_id(key, names);
        if selection.allows_key(id) {
            if let Some(id) = id {
                found.push(id);
            }
            items.push(CopyItem::Prop(key.clone(), value.clone()));
        }
    }
}

fn retain_new(items: &mut Vec<CopyItem>, dest: &ContentBag, overwrite: Overwrite) {
    if overwrite == Overwrite::Keep {
        items.retain(|item| match item {
            CopyItem::Prop(key, value) => dest.get(key.as_ref(), value.ptype()).is_none(),
            _ => true,
        });
    }
}

fn push_children(
    source: &MessageContent,
    dest: &MessageContent,
    selection: &Selection,
    overwrite: Overwrite,
    items: &mut Vec<CopyItem>,
) {
    if selection.allows(subobject::MESSAGE_RECIPIENTS.id())
        && (overwrite == Overwrite::Replace || dest.recipients.is_empty())
    {
        if overwrite == Overwrite::Replace {
            items.push(CopyItem::DeleteChildren(Children::Recipients));
        }
        items.extend(source.recipients.iter().cloned().map(CopyItem::Recipient));
    }
    if selection.allows(subobject::MESSAGE_ATTACHMENTS.id())
        && (overwrite == Overwrite::Replace || dest.attachments.is_empty())
    {
        if overwrite == Overwrite::Replace {
            items.push(CopyItem::DeleteChildren(Children::Attachments));
        }
        items.extend(source.attachments.iter().cloned().map(CopyItem::Attachment));
    }
}
