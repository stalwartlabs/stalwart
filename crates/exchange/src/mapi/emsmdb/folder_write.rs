/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{
    access::RopWrite,
    execute::{RopContext, RopError, RopResult},
    folder::{folder_data_type, stored_mailbox},
    folder_store::{PropTarget, RowEdit, is_folder_computed},
    message::{
        object_row::{encode_key, encode_property},
        write::owned_value,
    },
    state::{FolderObject, Handle, ServerObject},
};
use crate::{
    folders::{
        ContainerClass, FolderContents, FolderCreate, FolderEntry, FolderNode, FolderUpdate,
        FolderWriteError, FolderWrites, FolderWritten, SpecialFolder, WritableFolder,
        copy::{CopyCompletion, CopyDepth, CopyScope, FolderCopy, FolderCopyError, copy_source},
    },
    mapi::{ids::MapiId, text::decode_text},
    store::{FolderKind, FolderRef, folder::SearchDefinition, named::AccountNamedProps},
};
use exchange_proto::mapi::{
    ErrorCode,
    prop::{NamedPropMap, OwnedPropValue, PropKey, PropTag, PropValue, tags},
    rop::{
        DecodedRop,
        requests::{
            CopyFolder, CreateFolder, DeleteFolder, DeleteProperties, MoveFolder, SetProperties,
        },
        responses::{
            CopyFolderResponse, CreateFolderResponse, DeleteFolderResponse,
            DeletePropertiesResponse, MoveFolderResponse, PropertyProblem, SetPropertiesResponse,
        },
        views::MapiString,
    },
};
use smallvec::SmallVec;
use std::iter;
use types::type_state::DataType;

const FIRST_NAMED_ID: u16 = 0x8000;
const FOLDER_GENERIC: u8 = 1;
const FOLDER_SEARCH: u8 = 2;
const DEL_MESSAGES: u8 = 0x01;
const DEL_FOLDERS: u8 = 0x04;
const DELETE_HARD_DELETE: u8 = 0x10;
const DEL_BOTH: u8 = DEL_MESSAGES | DEL_FOLDERS;
const DEL_VALID: u8 = DEL_MESSAGES | DEL_FOLDERS | DELETE_HARD_DELETE;

#[derive(Clone, Copy)]
pub(super) struct OpenFolder {
    pub(super) mailbox_id: u32,
    pub(super) node: FolderNode,
}

impl From<FolderWriteError> for ErrorCode {
    fn from(err: FolderWriteError) -> Self {
        match err {
            FolderWriteError::NotFound | FolderWriteError::ParentNotFound => ErrorCode::NOT_FOUND,
            FolderWriteError::Forbidden | FolderWriteError::Protected => ErrorCode::ACCESS_DENIED,
            FolderWriteError::Unsupported => ErrorCode::NOT_SUPPORTED,
            FolderWriteError::EmptyName
            | FolderWriteError::NameTooLong
            | FolderWriteError::InvalidParent
            | FolderWriteError::InvalidSearch => ErrorCode::INVALID_PARAM,
            FolderWriteError::Cycle => ErrorCode::FOLDER_CYCLE,
            FolderWriteError::TooDeep => ErrorCode::TOO_COMPLEX,
            FolderWriteError::AlreadyExists(_) => ErrorCode::DUPLICATE_NAME,
            FolderWriteError::OverQuota => ErrorCode::QUOTA_EXCEEDED,
            FolderWriteError::HasChildren => ErrorCode::HAS_FOLDERS,
            FolderWriteError::HasItems => ErrorCode::HAS_MESSAGES,
            FolderWriteError::Conflict => ErrorCode::OBJECT_MODIFIED,
        }
    }
}

impl From<FolderWriteError> for RopError {
    fn from(err: FolderWriteError) -> Self {
        RopError::Code(err.into())
    }
}

impl RopContext<'_, '_> {
    pub(super) fn open_folder_at(&self, handle: Handle) -> Result<OpenFolder, RopError> {
        match self.state.get(handle) {
            Some(ServerObject::Folder(folder)) => Ok(OpenFolder {
                mailbox_id: folder.mailbox_id,
                node: folder
                    .id()
                    .and_then(MapiId::to_node)
                    .ok_or(ErrorCode::OBJECT_DELETED)?,
            }),
            Some(_) => Err(RopError::Code(ErrorCode::NOT_SUPPORTED)),
            None => Err(RopError::Code(ErrorCode::NULL_OBJECT)),
        }
    }

    async fn child_of(
        &mut self,
        parent: OpenFolder,
        folder_id: MapiId,
    ) -> Result<FolderNode, RopError> {
        let node = folder_id.to_node().ok_or(ErrorCode::NOT_FOUND)?;
        let tree = self.folder_tree(parent.mailbox_id).await?;
        match tree.get(node).and_then(|entry| entry.parent) {
            Some(entry_parent)
                if entry_parent == parent.node
                    || (parent.node == FolderNode::Special(SpecialFolder::Root)
                        && entry_parent == FolderNode::Special(SpecialFolder::Finder)) =>
            {
                Ok(node)
            }
            _ => Err(RopError::Code(ErrorCode::NOT_FOUND)),
        }
    }

    pub(super) fn check_folder_type(&self, node: FolderNode) -> Result<(), RopError> {
        match folder_data_type(node) {
            Some(data_type) if !self.types.contains(data_type) => {
                Err(RopError::Code(ErrorCode::ACCESS_DENIED))
            }
            _ => Ok(()),
        }
    }

    pub(super) fn check_writable(&self, kind: WritableFolder) -> Result<(), RopError> {
        let data_type = match kind {
            WritableFolder::Mailbox | WritableFolder::Virtual => DataType::Email,
            WritableFolder::Calendar => DataType::CalendarEvent,
            WritableFolder::AddressBook => DataType::ContactCard,
        };
        if self.types.contains(data_type) {
            Ok(())
        } else {
            Err(RopError::Code(ErrorCode::ACCESS_DENIED))
        }
    }

    fn folder_name(&self, name: &MapiString<'_>) -> String {
        let value = match *name {
            MapiString::Unicode(text) => PropValue::Unicode(text),
            MapiString::String8(bytes) => PropValue::String8(bytes),
        };
        let mut out = String::new();
        decode_text(&value, self.code_page(), &mut out);
        out
    }

    pub async fn create_folder(
        &mut self,
        rop: &DecodedRop<'_>,
        request: &CreateFolder<'_>,
    ) -> RopResult {
        let parent_handle = self.input(rop.header.input_handle)?;
        let parent = self.open_folder_at(parent_handle)?;
        let logon_id = self
            .state
            .logon_id(parent_handle)
            .ok_or(RopError::Code(ErrorCode::NULL_OBJECT))?;
        let search = match request.folder_type {
            FOLDER_GENERIC => None,
            FOLDER_SEARCH => Some(SearchDefinition::default()),
            _ => return Err(RopError::Code(ErrorCode::INVALID_PARAM)),
        };
        let name = self.folder_name(&request.display_name);
        let result = self
            .create_child_folder(parent, &name, None, search.as_ref())
            .await?;
        let (node, opened_existing) = match result {
            Ok(folder) => (FolderNode::Stored(folder), false),
            Err(FolderWriteError::AlreadyExists(node)) if request.open_existing => (node, true),
            Err(err) => return Err(err.into()),
        };
        self.invalidate_mailbox();
        if !opened_existing {
            let comment = self.folder_name(&request.comment);
            if !comment.is_empty() {
                let property = encode_property(
                    PropKey::tag(tags::COMMENT.id()).as_ref(),
                    &OwnedPropValue::Unicode(comment.into_boxed_str()),
                );
                self.edit_folder_row(
                    OpenFolder {
                        mailbox_id: parent.mailbox_id,
                        node,
                    },
                    &[RowEdit::Set(property.key, property.value)],
                )
                .await?;
            }
        }
        let id = MapiId::from_node(node);
        let handle = self.state.insert(
            logon_id,
            ServerObject::Folder(FolderObject::new(parent.mailbox_id, id)),
        )?;
        let index = request.output_handle_index;
        self.set_output(index, handle)?;
        let folder_id = if opened_existing {
            id.to_client(&self.mailbox(parent.mailbox_id).await?.exchange)
        } else {
            id
        };
        self.respond(
            rop,
            index,
            &CreateFolderResponse {
                folder_id: folder_id.to_eid(),
                existing: None,
            },
        )
    }

    pub(super) async fn create_child_folder(
        &mut self,
        parent: OpenFolder,
        name: &str,
        class: Option<&ContainerClass>,
        search: Option<&SearchDefinition>,
    ) -> Result<Result<FolderRef, FolderWriteError>, RopError> {
        let tree = self.folder_tree(parent.mailbox_id).await?;
        let entry = tree.get(parent.node).ok_or(ErrorCode::NOT_FOUND)?;
        let (kind, class) = match search {
            Some(_) => (WritableFolder::Virtual, None),
            None => {
                child_kind(parent.node, entry, class).unwrap_or((WritableFolder::Virtual, class))
            }
        };
        self.check_writable(kind)?;
        let request = self.request;
        Ok(request
            .server
            .folder_create(
                request.access_token,
                parent.mailbox_id,
                FolderCreate {
                    kind,
                    parent: parent.node,
                    name,
                    class: class.map(ContainerClass::as_str),
                    search,
                    client_key: None,
                },
            )
            .await?
            .map(|written| written.folder))
    }

    pub async fn delete_folder(
        &mut self,
        rop: &DecodedRop<'_>,
        index: u8,
        request: &DeleteFolder,
    ) -> RopResult {
        let parent = self.open_folder_at(self.input(rop.header.input_handle)?)?;
        let folder_id = self.folder_id(parent.mailbox_id, request.folder_id).await?;
        let flags = request.delete_folder_flags & DEL_VALID;
        let node = self.child_of(parent, folder_id).await?;
        self.check_folder_type(node)?;
        let contents = match flags & (DEL_MESSAGES | DEL_FOLDERS) {
            DEL_BOTH => FolderContents::Remove,
            DEL_MESSAGES if !self.has_subfolders(parent.mailbox_id, node).await? => {
                FolderContents::Remove
            }
            DEL_FOLDERS if !self.has_messages(parent.mailbox_id, node).await? => {
                FolderContents::Remove
            }
            _ => FolderContents::Keep,
        };
        let request_ctx = self.request;
        let result = request_ctx
            .server
            .folder_destroy(request_ctx.access_token, parent.mailbox_id, node, contents)
            .await?;
        self.invalidate_mailbox();
        let partial_completion = match result {
            Ok(_) => false,
            Err(
                FolderWriteError::HasChildren
                | FolderWriteError::HasItems
                | FolderWriteError::Forbidden,
            ) => true,
            Err(err) => return Err(err.into()),
        };
        self.respond(rop, index, &DeleteFolderResponse { partial_completion })
    }

    async fn has_subfolders(&mut self, mailbox_id: u32, node: FolderNode) -> trc::Result<bool> {
        Ok(self
            .folder_tree(mailbox_id)
            .await?
            .children(node)
            .next()
            .is_some())
    }

    async fn has_messages(&mut self, mailbox_id: u32, node: FolderNode) -> trc::Result<bool> {
        if stored_mailbox(node).is_none() {
            return Ok(true);
        }
        let tree = self.folder_tree(mailbox_id).await?;
        let counters = self.folder_counters(mailbox_id).await?;
        Ok(iter::once(node)
            .chain(tree.descendants(node).map(|entry| entry.node))
            .filter_map(stored_mailbox)
            .any(|id| counters.get(&id).is_some_and(|counters| counters.total > 0)))
    }

    pub async fn move_folder(
        &mut self,
        rop: &DecodedRop<'_>,
        index: u8,
        request: &MoveFolder<'_>,
    ) -> RopResult {
        let source = self.open_folder_at(self.input(rop.header.input_handle)?)?;
        let dest_handle = self
            .input(request.dest_handle_index)
            .map_err(|_| ErrorCode::DST_NULL_OBJECT)?;
        let dest = self.open_folder_at(dest_handle).map_err(|err| match err {
            RopError::Code(ErrorCode::NULL_OBJECT) => RopError::Code(ErrorCode::DST_NULL_OBJECT),
            err => err,
        })?;
        if dest.mailbox_id != source.mailbox_id {
            return Err(RopError::Code(ErrorCode::NOT_SUPPORTED));
        }
        let folder_id = self.folder_id(source.mailbox_id, request.folder_id).await?;
        let node = self.child_of(source, folder_id).await?;
        self.check_folder_type(node)?;
        let name = self.folder_name(&request.new_folder_name);
        let update = FolderUpdate {
            name: Some(name.as_str()),
            parent: (dest.node != source.node).then_some(dest.node),
        };
        let request_ctx = self.request;
        let result = request_ctx
            .server
            .folder_update(request_ctx.access_token, source.mailbox_id, node, update)
            .await?;
        self.invalidate_mailbox();
        let partial_completion = match result {
            Ok(_) => false,
            Err(FolderWriteError::Forbidden) => true,
            Err(err) => return Err(err.into()),
        };
        self.respond(rop, index, &MoveFolderResponse { partial_completion })
    }

    pub async fn copy_folder(
        &mut self,
        rop: &DecodedRop<'_>,
        index: u8,
        request: &CopyFolder<'_>,
    ) -> RopResult {
        let source = self.open_folder_at(self.input(rop.header.input_handle)?)?;
        let dest_handle = self
            .input(request.dest_handle_index)
            .map_err(|_| ErrorCode::DST_NULL_OBJECT)?;
        let dest = self.open_folder_at(dest_handle).map_err(|err| match err {
            RopError::Code(ErrorCode::NULL_OBJECT) => RopError::Code(ErrorCode::DST_NULL_OBJECT),
            err => err,
        })?;
        if dest.mailbox_id != source.mailbox_id {
            return Err(RopError::Code(ErrorCode::NOT_SUPPORTED));
        }
        let folder_id = self.folder_id(source.mailbox_id, request.folder_id).await?;
        let node = self.child_of(source, folder_id).await?;
        self.check_folder_type(node)?;
        self.check_writable(WritableFolder::Mailbox)?;
        let from = copy_source(node).ok_or(ErrorCode::NOT_SUPPORTED)?;
        let name = self.folder_name(&request.new_folder_name);
        let depth = if request.want_recursive {
            CopyDepth::Subtree
        } else {
            CopyDepth::Folder
        };
        let tree = self.folder_tree(source.mailbox_id).await?;
        if tree.in_subtree(node, dest.node) {
            return Err(FolderWriteError::Cycle.into());
        }
        let rights = self.view_rights(source.mailbox_id).await?;
        if !rights.of(node).reads_items()
            || (depth == CopyDepth::Subtree
                && tree.descendants(node).any(|child| {
                    copy_source(child.node).is_some() && !rights.of(child.node).reads_items()
                }))
        {
            return Err(RopError::Code(ErrorCode::ACCESS_DENIED));
        }
        let entry = tree.get(node).ok_or(ErrorCode::NOT_FOUND)?;
        let copied = FolderCopy {
            server: self.request.server,
            access_token: self.request.access_token,
            session_id: self.session_id(),
            account_id: source.mailbox_id,
            scope: CopyScope::Readable(&rights),
        }
        .copy(&tree, entry, from, dest.node, &name, depth)
        .await?;
        self.invalidate_mailbox();
        let completion = match copied {
            Ok((_, completion)) => completion,
            Err(FolderCopyError::Folder(err)) => return Err(err.into()),
            Err(FolderCopyError::MailboxLimit) => {
                return Err(RopError::Code(ErrorCode::QUOTA_EXCEEDED));
            }
            Err(FolderCopyError::Conflict) => {
                return Err(RopError::Code(ErrorCode::OBJECT_MODIFIED));
            }
        };
        self.respond(
            rop,
            index,
            &CopyFolderResponse {
                partial_completion: completion == CopyCompletion::Partial,
            },
        )
    }

    pub async fn set_properties(
        &mut self,
        rop: &DecodedRop<'_>,
        index: u8,
        request: &SetProperties<'_>,
    ) -> RopResult {
        let folder = self.open_folder_at(self.input(rop.header.input_handle)?)?;
        self.check_folder_type(folder.node)?;
        let tree = self.folder_tree(folder.mailbox_id).await?;
        let entry = tree.get(folder.node).ok_or(ErrorCode::OBJECT_DELETED)?;
        let exchange = self.mailbox(folder.mailbox_id).await?.exchange;
        let named = AccountNamedProps::new(&exchange);
        let stores_row = PropTarget::of(folder.node).is_some();
        let code_page = self.code_page();
        let mut problems = SmallVec::<[PropertyProblem; 8]>::new();
        let mut edited = SmallVec::<[(usize, PropTag); 8]>::new();
        let mut edits = SmallVec::<[RowEdit; 8]>::new();
        let mut rename = None;
        let mut reclass = None;
        let mut text = String::new();
        for (position, (tag, value)) in request.property_values.iter().enumerate() {
            let problem = if tag.id() == tags::DISPLAY_NAME.id() {
                if decode_text(&value, code_page, &mut text) {
                    if text.as_str() != &*entry.name {
                        rename = Some((position, tag, std::mem::take(&mut text)));
                    }
                    None
                } else {
                    Some(ErrorCode::INVALID_PARAM)
                }
            } else if tag.id() == tags::CONTAINER_CLASS.id() {
                let value = ContainerClass::wire_value(value);
                match decode_text(&value, code_page, &mut text)
                    .then(|| ContainerClass::parse(&text))
                {
                    Some(class) if class == entry.class => None,
                    Some(class) if is_virtual(folder.node) => {
                        reclass = Some((position, tag, class));
                        None
                    }
                    Some(class) => match class.family() {
                        None => Some(ErrorCode::INVALID_PARAM),
                        Some(WritableFolder::Mailbox) if stored_mailbox(folder.node).is_some() => {
                            edited.push((position, tag));
                            edits.push(RowEdit::Set(
                                ContainerClass::property_key(),
                                class.property_value(),
                            ));
                            None
                        }
                        Some(_) => Some(ErrorCode::NOT_SUPPORTED),
                    },
                    None => Some(ErrorCode::INVALID_PARAM),
                }
            } else if is_folder_computed(tag) {
                Some(ErrorCode::ACCESS_DENIED)
            } else if !stores_row {
                Some(ErrorCode::NOT_SUPPORTED)
            } else {
                match row_key(tag, &named).and_then(|key| {
                    owned_value(tag, &value, code_page)
                        .map(|value| encode_property(key.as_ref(), &value))
                        .ok_or(ErrorCode::INVALID_PARAM)
                }) {
                    Ok(property) => {
                        edited.push((position, tag));
                        edits.push(RowEdit::Set(property.key, property.value));
                        None
                    }
                    Err(error) => Some(error),
                }
            };
            if let Some(error) = problem {
                problems.push(PropertyProblem {
                    index: u16::try_from(position).unwrap_or(u16::MAX),
                    tag,
                    error,
                });
            }
        }
        if !edits.is_empty()
            && let Err(err) = self.edit_owned_folder_row(folder, &edits).await
        {
            let RopError::Code(error) = err else {
                return Err(err);
            };
            problems.extend(edited.iter().map(|(position, tag)| PropertyProblem {
                index: u16::try_from(*position).unwrap_or(u16::MAX),
                tag: *tag,
                error,
            }));
            problems.sort_unstable_by_key(|problem| problem.index);
        }
        if let Some((position, tag, name)) = rename {
            let request_ctx = self.request;
            let result = request_ctx
                .server
                .folder_update(
                    request_ctx.access_token,
                    folder.mailbox_id,
                    folder.node,
                    FolderUpdate {
                        name: Some(name.as_str()),
                        parent: None,
                    },
                )
                .await?;
            self.invalidate_mailbox();
            push_write_problem(&mut problems, position, tag, result)?;
        }
        if let Some((position, tag, class)) = reclass {
            let request_ctx = self.request;
            let result = request_ctx
                .server
                .folder_set_class(
                    request_ctx.access_token,
                    folder.mailbox_id,
                    folder.node,
                    class.as_str(),
                )
                .await?;
            self.invalidate_mailbox();
            push_write_problem(&mut problems, position, tag, result)?;
        }
        self.respond(
            rop,
            index,
            &SetPropertiesResponse {
                property_problems: &problems,
            },
        )
    }

    pub async fn delete_properties(
        &mut self,
        rop: &DecodedRop<'_>,
        index: u8,
        request: &DeleteProperties<'_>,
    ) -> RopResult {
        let folder = self.open_folder_at(self.input(rop.header.input_handle)?)?;
        self.check_folder_type(folder.node)?;
        let exchange = self.mailbox(folder.mailbox_id).await?.exchange;
        let named = AccountNamedProps::new(&exchange);
        let mut problems = SmallVec::<[PropertyProblem; 8]>::new();
        let mut edited = SmallVec::<[(usize, PropTag); 8]>::new();
        let mut edits = SmallVec::<[RowEdit; 8]>::new();
        for (position, tag) in request.property_tags.iter().enumerate() {
            if is_computed(tag) || is_folder_computed(tag) {
                problems.push(PropertyProblem {
                    index: u16::try_from(position).unwrap_or(u16::MAX),
                    tag,
                    error: ErrorCode::ACCESS_DENIED,
                });
            } else if let Ok(key) = row_key(tag, &named) {
                edited.push((position, tag));
                edits.push(RowEdit::Remove(encode_key(key.as_ref())));
            }
        }
        if !edits.is_empty()
            && PropTarget::of(folder.node).is_some()
            && let Err(err) = self.edit_owned_folder_row(folder, &edits).await
        {
            let RopError::Code(error) = err else {
                return Err(err);
            };
            problems.extend(edited.iter().map(|(position, tag)| PropertyProblem {
                index: u16::try_from(*position).unwrap_or(u16::MAX),
                tag: *tag,
                error,
            }));
            problems.sort_unstable_by_key(|problem| problem.index);
        }
        self.respond(
            rop,
            index,
            &DeletePropertiesResponse {
                property_problems: &problems,
            },
        )
    }

    pub(super) async fn edit_owned_folder_row(
        &mut self,
        folder: OpenFolder,
        edits: &[RowEdit],
    ) -> Result<(), RopError> {
        if !self.may_edit_folder_rows(folder.mailbox_id) {
            return Err(RopError::Code(ErrorCode::ACCESS_DENIED));
        }
        self.edit_folder_row(folder, edits).await
    }

    pub(super) fn may_edit_folder_rows(&self, mailbox_id: u32) -> bool {
        RopWrite::MemberOnly.admits(self.logon_access(mailbox_id))
    }
}

fn is_virtual(node: FolderNode) -> bool {
    matches!(
        node,
        FolderNode::Stored(FolderRef {
            kind: FolderKind::Virtual,
            ..
        })
    )
}

fn push_write_problem(
    problems: &mut SmallVec<[PropertyProblem; 8]>,
    position: usize,
    tag: PropTag,
    result: Result<FolderWritten, FolderWriteError>,
) -> Result<(), RopError> {
    match result {
        Ok(_) => Ok(()),
        Err(FolderWriteError::Forbidden) => Err(RopError::Code(ErrorCode::ACCESS_DENIED)),
        Err(err) => {
            problems.push(PropertyProblem {
                index: u16::try_from(position).unwrap_or(u16::MAX),
                tag,
                error: err.into(),
            });
            problems.sort_unstable_by_key(|problem| problem.index);
            Ok(())
        }
    }
}

pub(super) fn child_kind<'x>(
    parent: FolderNode,
    entry: &'x FolderEntry,
    class: Option<&'x ContainerClass>,
) -> Option<(WritableFolder, Option<&'x ContainerClass>)> {
    let inherited = match parent {
        FolderNode::Special(SpecialFolder::IpmSubtree) => None,
        _ if entry.ipm => Some(&entry.class),
        _ => return None,
    };
    let effective = class.or(inherited);
    if effective == Some(&ContainerClass::Task) && holds_task_lists(parent) {
        return Some((WritableFolder::Calendar, effective));
    }
    Some((
        effective.map_or(WritableFolder::Mailbox, WritableFolder::from_class),
        class,
    ))
}

fn holds_task_lists(parent: FolderNode) -> bool {
    matches!(
        parent,
        FolderNode::Special(
            SpecialFolder::IpmSubtree | SpecialFolder::Tasks | SpecialFolder::Calendar
        ) | FolderNode::Stored(FolderRef {
            kind: FolderKind::Calendar,
            ..
        })
    )
}

fn is_computed(tag: PropTag) -> bool {
    tag.id() == tags::DISPLAY_NAME.id() || tag.id() == tags::CONTAINER_CLASS.id()
}

pub(super) fn folder_row_key(
    tag: PropTag,
    named: &AccountNamedProps<'_>,
) -> Result<PropKey, ErrorCode> {
    if is_computed(tag) || is_folder_computed(tag) {
        return Err(ErrorCode::ACCESS_DENIED);
    }
    row_key(tag, named)
}

fn row_key(tag: PropTag, named: &AccountNamedProps<'_>) -> Result<PropKey, ErrorCode> {
    if tag.id().0 >= FIRST_NAMED_ID {
        named
            .key(tag.id())
            .map(|key| key.to_key())
            .ok_or(ErrorCode::NOT_FOUND)
    } else {
        Ok(PropKey::tag(tag.id()))
    }
}
