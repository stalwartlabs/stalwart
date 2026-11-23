/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::EwsRequest;
use crate::{
    ews::{
        schema::DistinguishedFolderName,
        types::{
            ids::{
                AttachmentId, BaseFolderId, BaseItemId, DistinguishedFolderId, ItemId,
                TargetFolderId,
            },
            item::Item,
        },
    },
    ids::ews::{EwsConversationId, EwsObjectId},
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RequestTarget<'a> {
    Caller,
    Mailbox(&'a str),
    Account(u32),
}

impl<'a> RequestTarget<'a> {
    fn of_folder(id: &'a BaseFolderId<'_>) -> Option<Self> {
        match id {
            BaseFolderId::Folder(id) => Self::of_object(id.id.as_str()),
            BaseFolderId::Distinguished(id) => Some(Self::of_distinguished(id)),
        }
    }

    fn of_target_folder(id: &'a TargetFolderId<'_>) -> Option<Self> {
        match id {
            TargetFolderId::Folder(id) => Self::of_object(id.id.as_str()),
            TargetFolderId::Distinguished(id) => Some(Self::of_distinguished(id)),
            TargetFolderId::AddressList(_) => None,
        }
    }

    fn of_distinguished(id: &'a DistinguishedFolderId<'_>) -> Self {
        id.mailbox
            .as_ref()
            .and_then(|mailbox| mailbox.email_address.as_deref())
            .filter(|address| !address.is_empty())
            .map_or(RequestTarget::Caller, RequestTarget::Mailbox)
    }

    fn of_item(id: &BaseItemId<'_>) -> Option<Self> {
        match id {
            BaseItemId::Item(id) => Self::of_item_id(id),
            BaseItemId::Occurrence { master, .. } => Self::of_object(master.as_str()),
            BaseItemId::RecurringMaster { occurrence, .. } => Self::of_object(occurrence.as_str()),
            BaseItemId::MasterRanges(ranges) => Self::of_item_id(&ranges.id),
        }
    }

    fn of_item_id(id: &ItemId<'_>) -> Option<Self> {
        Self::of_object(id.id.as_str())
    }

    fn of_attachment(id: &AttachmentId<'_>) -> Option<Self> {
        Self::of_object(id.id.as_str())
    }

    fn of_conversation(id: &ItemId<'_>) -> Option<Self> {
        EwsConversationId::decode(id.id.as_str())
            .map(|conversation| RequestTarget::Account(conversation.account))
    }

    fn of_object(id: &str) -> Option<Self> {
        EwsObjectId::decode(id).map(|id| RequestTarget::Account(id.account()))
    }
}

impl EwsRequest<'_> {
    pub fn target(&self) -> Option<RequestTarget<'_>> {
        match self {
            EwsRequest::GetFolder(request) => {
                request.folder_ids.iter().find_map(RequestTarget::of_folder)
            }
            EwsRequest::FindFolder(request) => request
                .parent_folder_ids
                .iter()
                .find_map(RequestTarget::of_folder),
            EwsRequest::FindItem(request) => request
                .parent_folder_ids
                .iter()
                .find_map(RequestTarget::of_folder),
            EwsRequest::DeleteFolder(request) => {
                request.folder_ids.iter().find_map(RequestTarget::of_folder)
            }
            EwsRequest::EmptyFolder(request) => {
                request.folder_ids.iter().find_map(RequestTarget::of_folder)
            }
            EwsRequest::MoveFolder(request) | EwsRequest::CopyFolder(request) => {
                request.folder_ids.iter().find_map(RequestTarget::of_folder)
            }
            EwsRequest::MarkAllItemsAsRead(request) => {
                request.folder_ids.iter().find_map(RequestTarget::of_folder)
            }
            EwsRequest::UpdateFolder(request) => request
                .folder_changes
                .iter()
                .find_map(|change| RequestTarget::of_folder(&change.id)),
            EwsRequest::CreateFolder(request) => {
                RequestTarget::of_target_folder(&request.parent_folder_id)
            }
            EwsRequest::CreateItem(request) => match request
                .saved_item_folder_id
                .as_ref()
                .and_then(RequestTarget::of_target_folder)
            {
                saved @ (None | Some(RequestTarget::Caller)) => request
                    .items
                    .iter()
                    .try_fold(None, |first, item| match item {
                        Item::ResponseObject(_, object) => Some(first.or_else(|| {
                            object
                                .extra
                                .reference_item_id
                                .as_ref()
                                .and_then(RequestTarget::of_item_id)
                        })),
                        _ => None,
                    })
                    .flatten()
                    .or(saved),
                saved => saved,
            },
            EwsRequest::SyncFolderHierarchy(request) => request
                .folder
                .as_ref()
                .and_then(RequestTarget::of_target_folder),
            EwsRequest::SyncFolderItems(request) => {
                RequestTarget::of_target_folder(&request.folder)
            }
            EwsRequest::FindConversation(request) => {
                RequestTarget::of_target_folder(&request.parent_folder_id)
            }
            EwsRequest::FindPeople(request) => match &request.parent_folder_id {
                Some(TargetFolderId::Distinguished(id))
                    if id.name == DistinguishedFolderName::Directory =>
                {
                    None
                }
                parent => parent.as_ref().and_then(RequestTarget::of_target_folder),
            },
            EwsRequest::GetItem(request) => {
                request.item_ids.iter().find_map(RequestTarget::of_item)
            }
            EwsRequest::DeleteItem(request) => {
                request.item_ids.iter().find_map(RequestTarget::of_item)
            }
            EwsRequest::MoveItem(request) | EwsRequest::CopyItem(request) => {
                request.item_ids.iter().find_map(RequestTarget::of_item)
            }
            EwsRequest::MarkAsJunk(request) => {
                request.item_ids.iter().find_map(RequestTarget::of_item)
            }
            EwsRequest::UpdateItem(request) => request
                .saved_item_folder_id
                .as_ref()
                .and_then(RequestTarget::of_target_folder)
                .or_else(|| {
                    request
                        .item_changes
                        .iter()
                        .find_map(|change| RequestTarget::of_item(&change.id))
                }),
            EwsRequest::SendItem(request) => request
                .item_ids
                .iter()
                .find_map(RequestTarget::of_item)
                .or_else(|| {
                    request
                        .saved_item_folder_id
                        .as_ref()
                        .and_then(RequestTarget::of_target_folder)
                }),
            EwsRequest::ArchiveItem(request) => {
                RequestTarget::of_target_folder(&request.archive_source_folder_id)
                    .or_else(|| request.item_ids.iter().find_map(RequestTarget::of_item))
            }
            EwsRequest::GetAttachment(request) => request
                .attachment_ids
                .iter()
                .find_map(RequestTarget::of_attachment),
            EwsRequest::DeleteAttachment(request) => request
                .attachment_ids
                .iter()
                .find_map(RequestTarget::of_attachment),
            EwsRequest::CreateAttachment(request) => {
                RequestTarget::of_item_id(&request.parent_item_id)
            }
            EwsRequest::GetConversationItems(request) => request
                .folders_to_ignore
                .iter()
                .flatten()
                .find_map(RequestTarget::of_folder)
                .or_else(|| {
                    request.conversations.iter().find_map(|conversation| {
                        RequestTarget::of_conversation(&conversation.conversation_id)
                    })
                }),
            EwsRequest::ExportItems(request) => {
                request.item_ids.iter().find_map(RequestTarget::of_item_id)
            }
            EwsRequest::UploadItems(request) => request
                .items
                .iter()
                .find_map(|item| RequestTarget::of_object(item.parent_folder_id.id.as_str())),
            _ => None,
        }
    }
}
