/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{
    FolderSelector, FolderVariant, cross_mailbox_status, crosses_mailbox, folder_id,
    folder_not_found, parent_folder_status, resolve_folder,
};
use crate::{
    ews::{
        context::{EwsCaller, EwsContext},
        item::{
            ItemError,
            edit::{Edited, commit_edits},
            find::mailbox_of,
            mail_allowed, may_write_mailbox,
        },
        reply::{RESPONSE_CAPACITY, ews_response},
    },
    folders::{
        ContainerClass, FolderContents, FolderCreate, FolderEntry, FolderNode, FolderTree,
        FolderUpdate, FolderWriteError, FolderWriteResult, FolderWrites, FolderWritten,
        SpecialFolder, WritableFolder, access::ItemWrite, rights::FolderRights,
    },
    store::{FolderKind, FolderRef},
};
use common::Server;
use email::cache::email::MessageCacheAccess;
use exchange_proto::ews::{
    MessageResult, Operation, Status,
    requests::folder::{CreateFolder, DeleteFolder, EmptyFolder, MoveCopyFolder, UpdateFolder},
    responses::folder::{EmptyMessage, FolderInfoMessage},
    schema::{DisposalType, ResponseCode, UnindexedField},
    types::{
        change::FolderChange,
        folder::{Folder, FolderFields},
        path::Path,
    },
};
use http_proto::HttpResponse;

const ACCESS_DENIED: &str = "The access token does not grant access to this folder.";
const PARENT_NOT_FOUND: &str = "The parent folder could not be found.";
const PROTECTED_DELETE: &str = "Distinguished folders cannot be deleted.";
const PROTECTED_MOVE: &str = "Distinguished folders cannot be moved or renamed.";
const UNSUPPORTED: &str = "This folder operation is not supported for this folder.";
const NAME: &str = "The folder name is empty or too long.";
const INVALID_PARENT: &str = "The folder cannot be placed under this parent.";
const CYCLE: &str = "A folder cannot be moved into its own subtree.";
const TOO_DEEP: &str = "The folder hierarchy is too deep.";
const EXISTS: &str = "A folder with this name already exists.";
const QUOTA: &str = "The folder quota is exceeded.";
const NOT_EMPTY: &str = "The folder still has items or subfolders.";
const INVALID_SEARCH: &str = "The search folder definition is invalid.";
const CONFLICT: &str = "The folder changed while it was being saved; retry the request.";
const PROPERTY_SET: &str = "Only the display name of a folder can be changed.";
const UPDATE_PROPERTY_COUNT: &str =
    "An object within a change description must contain one and only one property to modify.";
const SET_ACTION: &str = "Set action is invalid for property.";
const CANNOT_EMPTY: &str = "Only mail folders can be emptied.";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum FolderOp {
    Delete,
    Place,
    Update,
}

pub(crate) async fn create_folder(
    server: &Server,
    ctx: &EwsContext,
    caller: EwsCaller<'_>,
    request: &CreateFolder<'_>,
) -> trc::Result<HttpResponse> {
    let account_id = ctx.account.account_id;
    let tree = ctx.folder_tree(server).await?;
    let parent = resolve_folder(
        server,
        ctx,
        &tree,
        FolderSelector::from(&request.parent_folder_id),
    )
    .await?
    .map(|entry| entry.node)
    .map_err(|status| parent_folder_status(ctx, status));
    let mut results = Vec::with_capacity(request.folders.len());
    for folder in &request.folders {
        let fields = folder.fields();
        if fields.total_count.is_some()
            || fields.child_folder_count.is_some()
            || fields.unread_count.is_some()
            || fields.effective_rights.is_some()
            || fields.sharing_effective_rights.is_some()
            || fields.managed_folder_information.is_some()
        {
            results.push(Err(Status::error(
                ResponseCode::ErrorInvalidPropertySet,
                SET_ACTION,
            )));
            continue;
        }
        let parent = match &parent {
            Ok(parent) => *parent,
            Err(status) => {
                results.push(Err(status.clone()));
                continue;
            }
        };
        let class = match folder {
            Folder::Tasks(_) => Some(
                fields
                    .folder_class
                    .as_deref()
                    .unwrap_or(ContainerClass::Task.as_str()),
            ),
            _ => fields.folder_class.as_deref(),
        };
        let container = class.map(ContainerClass::parse);
        let kind = match folder {
            Folder::Folder(_) | Folder::Tasks(_) if container == Some(ContainerClass::Task) => {
                WritableFolder::Calendar
            }
            Folder::Folder(_) => container
                .as_ref()
                .map_or(WritableFolder::Mailbox, WritableFolder::from_class),
            Folder::Tasks(_) => WritableFolder::Mailbox,
            Folder::Calendar(_) => WritableFolder::Calendar,
            Folder::Contacts(_) => WritableFolder::AddressBook,
            Folder::Search(_) => {
                results.push(Err(write_status(
                    FolderWriteError::Unsupported,
                    FolderOp::Place,
                )));
                continue;
            }
        };
        if !ctx.account.data_types.contains(kind.data_type()) {
            results.push(Err(write_status(
                FolderWriteError::Forbidden,
                FolderOp::Place,
            )));
            continue;
        }
        let variant = match kind {
            _ if container == Some(ContainerClass::Task) => FolderVariant::Tasks,
            WritableFolder::Calendar => FolderVariant::Calendar,
            WritableFolder::AddressBook => FolderVariant::Contacts,
            WritableFolder::Mailbox | WritableFolder::Virtual => FolderVariant::Folder,
        };
        let result = server
            .folder_create(
                caller.access_token,
                account_id,
                FolderCreate {
                    kind,
                    parent,
                    name: fields.display_name.as_deref().unwrap_or_default(),
                    class,
                    search: None,
                    client_key: None,
                },
            )
            .await?;
        ctx.folders_changed();
        results.push(
            result
                .map(|written| written_folder(account_id, written, variant))
                .map_err(|err| write_status(err, FolderOp::Place)),
        );
    }
    Ok(folder_info_response(ctx, Operation::CreateFolder, results))
}

pub(crate) async fn update_folder(
    server: &Server,
    ctx: &EwsContext,
    caller: EwsCaller<'_>,
    request: &UpdateFolder<'_>,
) -> trc::Result<HttpResponse> {
    let account_id = ctx.account.account_id;
    let tree = ctx.folder_tree(server).await?;
    let mut results = Vec::with_capacity(request.folder_changes.len());
    for change in &request.folder_changes {
        let entry =
            match resolve_folder(server, ctx, &tree, FolderSelector::from(&change.id)).await? {
                Ok(entry) => entry,
                Err(status) => {
                    results.push(Err(status));
                    continue;
                }
            };
        let name = match new_name(&change.changes, &entry.class) {
            Ok(name) => name,
            Err(error) => {
                results.push(Err(error.status()));
                continue;
            }
        };
        let result = server
            .folder_update(
                caller.access_token,
                account_id,
                entry.node,
                FolderUpdate {
                    name: Some(name),
                    parent: None,
                },
            )
            .await?;
        ctx.folders_changed();
        results.push(
            result
                .map(|written| written_folder(account_id, written, FolderVariant::of(entry)))
                .map_err(|err| write_status(err, FolderOp::Update)),
        );
    }
    Ok(folder_info_response(ctx, Operation::UpdateFolder, results))
}

pub(crate) async fn move_folder(
    server: &Server,
    ctx: &EwsContext,
    caller: EwsCaller<'_>,
    request: &MoveCopyFolder<'_>,
) -> trc::Result<HttpResponse> {
    let account_id = ctx.account.account_id;
    let tree = ctx.folder_tree(server).await?;
    let to = if crosses_mailbox(ctx, &request.to_folder_id) {
        Err(cross_mailbox_status())
    } else {
        resolve_folder(
            server,
            ctx,
            &tree,
            FolderSelector::from(&request.to_folder_id),
        )
        .await?
        .map(|entry| entry.node)
    };
    let mut results = Vec::with_capacity(request.folder_ids.len());
    for id in &request.folder_ids {
        let to = match &to {
            Ok(to) => *to,
            Err(status) => {
                results.push(Err(status.clone()));
                continue;
            }
        };
        let entry = match resolve_folder(server, ctx, &tree, FolderSelector::from(id)).await? {
            Ok(entry) => entry,
            Err(status) => {
                results.push(Err(status));
                continue;
            }
        };
        if ctx.access.hides_descendant(entry.node) {
            results.push(Err(write_status(
                FolderWriteError::Forbidden,
                FolderOp::Place,
            )));
            continue;
        }
        let result = server
            .folder_update(
                caller.access_token,
                account_id,
                entry.node,
                FolderUpdate {
                    name: None,
                    parent: Some(to),
                },
            )
            .await?;
        ctx.folders_changed();
        results.push(
            result
                .map(|written| written_folder(account_id, written, FolderVariant::of(entry)))
                .map_err(|err| write_status(err, FolderOp::Place)),
        );
    }
    Ok(folder_info_response(ctx, Operation::MoveFolder, results))
}

pub(crate) async fn delete_folder(
    server: &Server,
    ctx: &EwsContext,
    caller: EwsCaller<'_>,
    request: &DeleteFolder<'_>,
) -> trc::Result<HttpResponse> {
    let account_id = ctx.account.account_id;
    let tree = ctx.folder_tree(server).await?;
    let trash = deleted_items(&tree, request.delete_type);
    let mut statuses = Vec::with_capacity(request.folder_ids.len());
    for id in &request.folder_ids {
        let entry = match resolve_folder(server, ctx, &tree, FolderSelector::from(id)).await? {
            Ok(entry) => entry,
            Err(status) => {
                statuses.push(status);
                continue;
            }
        };
        let trash = match (entry.node, trash) {
            (
                FolderNode::Stored(FolderRef {
                    kind: FolderKind::Calendar | FolderKind::AddressBook,
                    ..
                }),
                _,
            ) => None,
            (node, Ok(trash)) => outside(&tree, trash, node),
            (_, Err(err)) => {
                statuses.push(err.status());
                continue;
            }
        };
        let result = discard(server, ctx, caller, account_id, entry.node, trash).await?;
        statuses.push(match result {
            Ok(_) => Status::SUCCESS,
            Err(err) => write_status(err, FolderOp::Delete),
        });
    }
    Ok(empty_response(ctx, Operation::DeleteFolder, statuses))
}

pub(crate) async fn empty_folder(
    server: &Server,
    ctx: &EwsContext,
    caller: EwsCaller<'_>,
    request: &EmptyFolder<'_>,
) -> trc::Result<HttpResponse> {
    let account_id = ctx.account.account_id;
    let tree = ctx.folder_tree(server).await?;
    let trash = deleted_items(&tree, request.delete_type);
    let mut statuses = Vec::with_capacity(request.folder_ids.len());
    for id in &request.folder_ids {
        let entry = match resolve_folder(server, ctx, &tree, FolderSelector::from(id)).await? {
            Ok(entry) => entry,
            Err(status) => {
                statuses.push(status);
                continue;
            }
        };
        let Some(mailbox_id) = mailbox_of(entry.node) else {
            statuses.push(Status::error(
                ResponseCode::ErrorCannotEmptyFolder,
                CANNOT_EMPTY,
            ));
            continue;
        };
        if let Err(err) = mail_allowed(ctx) {
            statuses.push(err.status());
            continue;
        }
        let trash = match trash {
            Ok(trash) => trash,
            Err(err) => {
                statuses.push(err.status());
                continue;
            }
        };
        let trash_id = match trash.map(mailbox_of) {
            Some(None) => {
                statuses.push(ItemError::NoDeletedItems.status());
                continue;
            }
            trash_id => trash_id
                .flatten()
                .filter(|trash_id| *trash_id != mailbox_id),
        };
        if !may_write_mailbox(ctx, mailbox_id, ItemWrite::Delete)
            || trash_id.is_some_and(|trash_id| !may_write_mailbox(ctx, trash_id, ItemWrite::Create))
        {
            statuses.push(ItemError::CannotDelete.status());
            continue;
        }
        statuses.push(
            match empty_mailbox(server, ctx, caller, mailbox_id, trash_id).await? {
                Err(err) => err.status(),
                Ok(()) if request.delete_sub_folders => {
                    let trash = outside(&tree, trash, entry.node);
                    remove_children(server, ctx, caller, account_id, &tree, entry, trash).await?
                }
                Ok(()) => Status::SUCCESS,
            },
        );
    }
    Ok(empty_response(ctx, Operation::EmptyFolder, statuses))
}

async fn empty_mailbox(
    server: &Server,
    ctx: &EwsContext,
    caller: EwsCaller<'_>,
    mailbox_id: u32,
    trash_id: Option<u32>,
) -> trc::Result<Result<(), ItemError>> {
    let account_id = ctx.account.account_id;
    let committed = commit_edits(server, caller, account_id, &[mailbox_id], |round, _| {
        let cache = round.cache;
        for message in cache.in_mailbox(mailbox_id) {
            let document_id = message.document_id();
            let Some(data) = cache.message_data(document_id) else {
                continue;
            };
            if round.claim(document_id).is_err() {
                continue;
            }
            match trash_id {
                Some(trash_id) => {
                    round
                        .edits
                        .move_to(document_id, data, mailbox_id, trash_id)?;
                }
                None => {
                    round.edits.remove_from(document_id, data, mailbox_id)?;
                }
            }
        }
        Ok(Ok(Edited::Done))
    })
    .await?;
    Ok(committed
        .outcomes
        .into_iter()
        .next()
        .unwrap_or(Ok(Edited::Done))
        .map(|_| ()))
}

async fn remove_children(
    server: &Server,
    ctx: &EwsContext,
    caller: EwsCaller<'_>,
    account_id: u32,
    tree: &FolderTree,
    entry: &FolderEntry,
    trash: Option<FolderNode>,
) -> trc::Result<Status<'static>> {
    for child in tree.children(entry.node) {
        if let Err(err) = discard(server, ctx, caller, account_id, child.node, trash).await?
            && err != FolderWriteError::NotFound
        {
            return Ok(write_status(err, FolderOp::Delete));
        }
    }
    Ok(Status::SUCCESS)
}

async fn discard(
    server: &Server,
    ctx: &EwsContext,
    caller: EwsCaller<'_>,
    account_id: u32,
    folder: FolderNode,
    trash: Option<FolderNode>,
) -> FolderWriteResult {
    let result = match trash {
        Some(_)
            if ctx.access.hides_descendant(folder)
                || !ctx.access.of(folder).contains(FolderRights::DELETE_ANY) =>
        {
            Ok(Err(FolderWriteError::Forbidden))
        }
        Some(trash) => {
            server
                .folder_update(
                    caller.access_token,
                    account_id,
                    folder,
                    FolderUpdate {
                        name: None,
                        parent: Some(trash),
                    },
                )
                .await
        }
        None => {
            server
                .folder_destroy(
                    caller.access_token,
                    account_id,
                    folder,
                    FolderContents::Remove,
                )
                .await
        }
    };
    if matches!(result, Ok(Ok(_))) {
        ctx.folders_changed();
    }
    result
}

fn deleted_items(
    tree: &FolderTree,
    delete_type: DisposalType,
) -> Result<Option<FolderNode>, ItemError> {
    match delete_type {
        DisposalType::MoveToDeletedItems => tree
            .special(SpecialFolder::DeletedItems)
            .map(|entry| Some(entry.node))
            .ok_or(ItemError::NoDeletedItems),
        DisposalType::HardDelete | DisposalType::SoftDelete => Ok(None),
    }
}

fn outside(tree: &FolderTree, trash: Option<FolderNode>, node: FolderNode) -> Option<FolderNode> {
    trash.filter(|trash| !tree.in_subtree(*trash, node))
}

#[derive(Debug, Clone, Copy)]
enum NameError {
    PropertySet,
    PropertyCount,
}

impl NameError {
    fn status(self) -> Status<'static> {
        match self {
            NameError::PropertySet => {
                Status::error(ResponseCode::ErrorInvalidPropertySet, PROPERTY_SET)
            }
            NameError::PropertyCount => Status::error(
                ResponseCode::ErrorIncorrectUpdatePropertyCount,
                UPDATE_PROPERTY_COUNT,
            ),
        }
    }
}

fn new_name<'x>(
    changes: &'x [FolderChange<'x>],
    class: &ContainerClass,
) -> Result<&'x str, NameError> {
    let mut name = None;
    for change in changes {
        let FolderChange::Set { path, value } = change else {
            return Err(NameError::PropertySet);
        };
        let fields = value.fields();
        if fields.field_count() > 1 {
            return Err(NameError::PropertyCount);
        }
        match path {
            Path::Field(UnindexedField::FolderDisplayName) => {
                name = Some(
                    fields
                        .display_name
                        .as_deref()
                        .ok_or(NameError::PropertySet)?,
                );
            }
            Path::Field(UnindexedField::FolderFolderClass)
                if fields
                    .folder_class
                    .as_deref()
                    .is_some_and(|value| ContainerClass::parse(value) == *class) => {}
            _ => return Err(NameError::PropertySet),
        }
    }
    name.ok_or(NameError::PropertySet)
}

pub(super) fn written_folder(
    account_id: u32,
    written: FolderWritten,
    variant: FolderVariant,
) -> Folder<'static> {
    variant.wrap(FolderFields {
        folder_id: Some(folder_id(
            account_id,
            FolderNode::Stored(written.folder),
            written.change_id.unwrap_or_default(),
        )),
        ..Default::default()
    })
}

pub(super) fn folder_info_response(
    ctx: &EwsContext,
    operation: Operation,
    results: Vec<Result<Folder<'static>, Status<'static>>>,
) -> HttpResponse {
    let mut out = Vec::with_capacity(RESPONSE_CAPACITY);
    let mut messages = ctx.envelope(&mut out).shape_a(operation);
    for result in results {
        match result {
            Ok(folder) => messages.message(&MessageResult {
                status: Status::SUCCESS,
                body: Some(FolderInfoMessage {
                    folders: vec![folder],
                }),
            }),
            Err(status) => {
                messages.message(&MessageResult::<FolderInfoMessage> { status, body: None })
            }
        }
    }
    messages.finish();
    ews_response(out)
}

fn empty_response(
    ctx: &EwsContext,
    operation: Operation,
    statuses: Vec<Status<'static>>,
) -> HttpResponse {
    let mut out = Vec::with_capacity(RESPONSE_CAPACITY);
    let mut messages = ctx.envelope(&mut out).shape_a(operation);
    for status in statuses {
        messages.message(&MessageResult::<EmptyMessage> { status, body: None });
    }
    messages.finish();
    ews_response(out)
}

pub(crate) fn write_status(err: FolderWriteError, op: FolderOp) -> Status<'static> {
    match err {
        FolderWriteError::NotFound => folder_not_found(),
        FolderWriteError::ParentNotFound => {
            Status::error(ResponseCode::ErrorParentFolderNotFound, PARENT_NOT_FOUND)
        }
        FolderWriteError::Forbidden => match op {
            FolderOp::Place => Status::error(ResponseCode::ErrorAccessDenied, ACCESS_DENIED),
            FolderOp::Update => {
                Status::error(ResponseCode::ErrorFolderSavePropertyError, ACCESS_DENIED)
            }
            FolderOp::Delete => Status::error(ResponseCode::ErrorCannotDeleteObject, ACCESS_DENIED),
        },
        FolderWriteError::Protected => match op {
            FolderOp::Delete => Status::error(
                ResponseCode::ErrorDeleteDistinguishedFolder,
                PROTECTED_DELETE,
            ),
            FolderOp::Place | FolderOp::Update => {
                Status::error(ResponseCode::ErrorMoveDistinguishedFolder, PROTECTED_MOVE)
            }
        },
        FolderWriteError::Unsupported => {
            Status::error(ResponseCode::ErrorInvalidOperation, UNSUPPORTED)
        }
        FolderWriteError::EmptyName | FolderWriteError::NameTooLong => {
            Status::error(ResponseCode::ErrorFolderSavePropertyError, NAME)
        }
        FolderWriteError::InvalidParent => {
            Status::error(ResponseCode::ErrorInvalidParentFolder, INVALID_PARENT)
        }
        FolderWriteError::Cycle => Status::error(ResponseCode::ErrorMoveCopyFailed, CYCLE),
        FolderWriteError::TooDeep => Status::error(ResponseCode::ErrorFolderSave, TOO_DEEP),
        FolderWriteError::AlreadyExists(_) => {
            Status::error(ResponseCode::ErrorFolderExists, EXISTS)
        }
        FolderWriteError::OverQuota => Status::error(ResponseCode::ErrorQuotaExceeded, QUOTA),
        FolderWriteError::HasChildren | FolderWriteError::HasItems => {
            Status::error(ResponseCode::ErrorFolderSave, NOT_EMPTY)
        }
        FolderWriteError::InvalidSearch => {
            Status::error(ResponseCode::ErrorInvalidRestriction, INVALID_SEARCH)
        }
        FolderWriteError::Conflict => {
            Status::error(ResponseCode::ErrorInternalServerTransientError, CONFLICT)
        }
    }
}
