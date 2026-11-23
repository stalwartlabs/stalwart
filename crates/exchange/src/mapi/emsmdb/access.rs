/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

pub use crate::folders::access::{DelegateRights, ItemWrite, LogonAccess, ViewRights};

use super::{
    execute::{RopContext, RopError},
    props::PropBag,
    state::{Handle, ServerObject, StreamOwner},
};
use crate::{
    folders::{FolderNode, rights::FolderRights},
    mapi::ids::MapiId,
};
use common::GroupwareResources;
use exchange_proto::mapi::{
    ErrorCode,
    prop::tags,
    rop::{RopId, RopRequest},
};
use groupware::{cache::GroupwareCache, calendar::privacy::EventViewer};
use std::sync::Arc;
use types::{collection::SyncCollection, type_state::DataType};

const RESPONSE_FLAG_RESERVED: u8 = 0x01;
const RESPONSE_FLAG_OWNER: u8 = 0x02;
const RESPONSE_FLAG_SEND_AS: u8 = 0x04;
pub(super) const RESPONSE_FLAG_OOF: u8 = 0x10;

impl LogonAccess {
    pub fn response_flags(self) -> u8 {
        match self {
            LogonAccess::Owner | LogonAccess::Member => {
                RESPONSE_FLAG_RESERVED | RESPONSE_FLAG_OWNER | RESPONSE_FLAG_SEND_AS
            }
            LogonAccess::Delegate => RESPONSE_FLAG_RESERVED,
        }
    }
}

impl FolderRights {
    pub fn push_props(self, bag: &mut PropBag) {
        bag.push_i32(tags::RIGHTS, self.bits());
        bag.push_i32(tags::ACCESS, self.access());
    }

    pub fn push_message_props(self, node: FolderNode, associated: bool, bag: &mut PropBag) {
        let access = self.message_access(node, associated);
        bag.push_i32(tags::ACCESS, access);
        bag.push_i32(
            tags::ACCESS_LEVEL,
            i32::from(access & Self::ACCESS_MODIFY != 0),
        );
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RopWrite {
    Read,
    Checked,
    MemberOnly,
    OwnerOnly,
}

impl RopWrite {
    pub fn of(request: &RopRequest<'_>) -> Self {
        match request {
            RopRequest::Release
            | RopRequest::Logon(_)
            | RopRequest::OpenFolder(_)
            | RopRequest::OpenMessage(_)
            | RopRequest::GetHierarchyTable(_)
            | RopRequest::GetContentsTable(_)
            | RopRequest::GetPropertiesSpecific(_)
            | RopRequest::GetPropertiesAll(_)
            | RopRequest::GetPropertiesList
            | RopRequest::ReadRecipients(_)
            | RopRequest::ReloadCachedInformation
            | RopRequest::SetColumns(_)
            | RopRequest::SortTable(_)
            | RopRequest::Restrict(_)
            | RopRequest::QueryRows(_)
            | RopRequest::QueryPosition
            | RopRequest::SeekRow(_)
            | RopRequest::SeekRowBookmark(_)
            | RopRequest::SeekRowFractional(_)
            | RopRequest::CreateBookmark
            | RopRequest::FreeBookmark(_)
            | RopRequest::FindRow(_)
            | RopRequest::ExpandRow(_)
            | RopRequest::CollapseRow(_)
            | RopRequest::GetCollapseState(_)
            | RopRequest::SetCollapseState(_)
            | RopRequest::GetMessageStatus(_)
            | RopRequest::GetAttachmentTable(_)
            | RopRequest::OpenAttachment(_)
            | RopRequest::OpenEmbeddedMessage(_)
            | RopRequest::GetReceiveFolder(_)
            | RopRequest::PublicFolderIsGhosted(_)
            | RopRequest::GetReceiveFolderTable
            | RopRequest::RegisterNotification(_)
            | RopRequest::OpenStream(_)
            | RopRequest::ReadStream(_)
            | RopRequest::SeekStream(_)
            | RopRequest::GetStreamSize
            | RopRequest::GetSearchCriteria(_)
            | RopRequest::GetPermissionsTable(_)
            | RopRequest::GetRulesTable(_)
            | RopRequest::LongTermIdFromId(_)
            | RopRequest::IdFromLongTermId(_)
            | RopRequest::GetAddressTypes
            | RopRequest::GetTransportFolder
            | RopRequest::GetNamesFromPropertyIds(_)
            | RopRequest::GetPropertyIdsFromNames(_)
            | RopRequest::QueryNamedProperties(_)
            | RopRequest::FastTransferSourceCopyMessages(_)
            | RopRequest::FastTransferSourceCopyFolder(_)
            | RopRequest::FastTransferSourceCopyTo(_)
            | RopRequest::FastTransferSourceCopyProperties(_)
            | RopRequest::FastTransferSourceGetBuffer(_)
            | RopRequest::TellVersion(_)
            | RopRequest::SynchronizationConfigure(_)
            | RopRequest::SynchronizationUploadStateStreamBegin(_)
            | RopRequest::SynchronizationUploadStateStreamContinue(_)
            | RopRequest::SynchronizationUploadStateStreamEnd
            | RopRequest::SynchronizationGetTransferState(_) => RopWrite::Read,
            RopRequest::CreateFolder(_)
            | RopRequest::DeleteFolder(_)
            | RopRequest::MoveFolder(_)
            | RopRequest::CopyFolder(_)
            | RopRequest::SetProperties(_)
            | RopRequest::DeleteProperties(_)
            | RopRequest::CreateMessage(_)
            | RopRequest::SaveChangesMessage(_)
            | RopRequest::RemoveAllRecipients(_)
            | RopRequest::ModifyRecipients(_)
            | RopRequest::SetMessageReadFlag(_)
            | RopRequest::DeleteMessages(_)
            | RopRequest::HardDeleteMessages(_)
            | RopRequest::HardDeleteMessagesAndSubfolders(_)
            | RopRequest::EmptyFolder(_)
            | RopRequest::MoveCopyMessages(_)
            | RopRequest::CreateAttachment(_)
            | RopRequest::DeleteAttachment(_)
            | RopRequest::SaveChangesAttachment(_)
            | RopRequest::WriteStream(_)
            | RopRequest::WriteStreamExtended(_)
            | RopRequest::CopyToStream(_)
            | RopRequest::CopyProperties(_)
            | RopRequest::CopyTo(_)
            | RopRequest::SetStreamSize(_)
            | RopRequest::CommitStream
            | RopRequest::SetReadFlags(_)
            | RopRequest::SetSearchCriteria(_)
            | RopRequest::FastTransferDestinationConfigure(_)
            | RopRequest::FastTransferDestinationPutBuffer(_)
            | RopRequest::FastTransferDestinationPutBufferExtended(_)
            | RopRequest::SynchronizationImportMessageChange(_)
            | RopRequest::SynchronizationImportHierarchyChange(_)
            | RopRequest::SynchronizationImportDeletes(_)
            | RopRequest::SynchronizationImportMessageMove(_)
            | RopRequest::SynchronizationImportReadStateChanges(_)
            | RopRequest::SynchronizationOpenCollector(_)
            | RopRequest::GetLocalReplicaIds(_)
            | RopRequest::ModifyPermissions(_) => RopWrite::Checked,
            RopRequest::SubmitMessage(_) | RopRequest::Stub(RopId::TRANSPORT_SEND, _) => {
                RopWrite::MemberOnly
            }
            RopRequest::SetMessageStatus(_)
            | RopRequest::ModifyRules(_)
            | RopRequest::SetReceiveFolder(_) => RopWrite::OwnerOnly,
            RopRequest::Stub(
                RopId::GET_PER_USER_LONG_TERM_IDS
                | RopId::QUERY_COLUMNS_ALL
                | RopId::RESET_TABLE
                | RopId::GET_STATUS
                | RopId::ABORT
                | RopId::OPTIONS_DATA,
                _,
            ) => RopWrite::Read,
            RopRequest::Stub(..) => RopWrite::OwnerOnly,
        }
    }

    pub fn admits(self, access: Option<LogonAccess>) -> bool {
        match self {
            RopWrite::Read | RopWrite::Checked => true,
            RopWrite::MemberOnly => {
                matches!(access, Some(LogonAccess::Owner | LogonAccess::Member))
            }
            RopWrite::OwnerOnly => access == Some(LogonAccess::Owner),
        }
    }
}

impl ServerObject {
    pub fn mailbox_id(&self) -> Option<u32> {
        match self {
            ServerObject::Logon(logon) => Some(logon.mailbox_id),
            ServerObject::Folder(folder) => Some(folder.mailbox_id),
            ServerObject::Table(table) => Some(table.folder.mailbox_id),
            ServerObject::Message(message) => Some(message.mailbox_id),
            ServerObject::Attachment(attachment) => Some(attachment.message.mailbox_id),
            ServerObject::Stream(stream) => Some(match &stream.owner {
                StreamOwner::Folder(folder) => folder.mailbox_id,
                StreamOwner::Message(message) => message.mailbox_id,
                StreamOwner::Attachment(attachment) => attachment.message.mailbox_id,
            }),
            ServerObject::Transfer(transfer) => Some(transfer.folder.mailbox_id),
            ServerObject::Subscription(_) => None,
        }
    }
}

impl RopContext<'_, '_> {
    pub fn logon_access(&self, mailbox_id: u32) -> Option<LogonAccess> {
        LogonAccess::of(self.request.access_token, mailbox_id)
    }

    pub fn event_viewer(&self, mailbox_id: u32) -> EventViewer {
        EventViewer::new(LogonAccess::reads_all(self.logon_access(mailbox_id)))
    }

    pub fn may_write(&self, request: &RopRequest<'_>, input: u8) -> Result<(), RopError> {
        let write = RopWrite::of(request);
        if matches!(write, RopWrite::Read | RopWrite::Checked) {
            return Ok(());
        }
        let admitted = self
            .input(input)
            .ok()
            .and_then(|handle: Handle| self.state.get(handle))
            .and_then(ServerObject::mailbox_id)
            .is_none_or(|mailbox_id| write.admits(self.logon_access(mailbox_id)));
        if admitted {
            Ok(())
        } else {
            Err(RopError::Code(ErrorCode::ACCESS_DENIED))
        }
    }

    pub async fn write_allowed(
        &mut self,
        mailbox_id: u32,
        folder: u64,
        write: ItemWrite,
    ) -> Result<bool, RopError> {
        match self.require_write(mailbox_id, folder, write).await {
            Ok(()) => Ok(true),
            Err(RopError::Code(ErrorCode::ACCESS_DENIED)) => Ok(false),
            Err(err) => Err(err),
        }
    }

    pub async fn require_write(
        &mut self,
        mailbox_id: u32,
        folder: u64,
        write: ItemWrite,
    ) -> Result<(), RopError> {
        if self.request.access_token.is_account_id(mailbox_id) {
            return Ok(());
        }
        let node = MapiId::from_counter(folder)
            .and_then(MapiId::to_node)
            .ok_or(ErrorCode::NOT_FOUND)?;
        self.require_node_write(mailbox_id, node, write).await
    }

    pub async fn require_node_write(
        &mut self,
        mailbox_id: u32,
        node: FolderNode,
        write: ItemWrite,
    ) -> Result<(), RopError> {
        if self.request.access_token.is_account_id(mailbox_id)
            || self
                .folder_rights(mailbox_id, node)
                .await?
                .contains(write.needs(node))
        {
            Ok(())
        } else {
            Err(RopError::Code(ErrorCode::ACCESS_DENIED))
        }
    }

    pub async fn view_rights(&mut self, mailbox_id: u32) -> trc::Result<ViewRights> {
        match self.logon_access(mailbox_id) {
            Some(LogonAccess::Owner) => Ok(ViewRights::Owner),
            Some(LogonAccess::Member) => Ok(ViewRights::Member),
            None => Ok(ViewRights::Revoked),
            Some(LogonAccess::Delegate) => {
                if let Some(rights) = self.cached_rights(mailbox_id) {
                    return Ok(ViewRights::Delegate(rights));
                }
                let tree = self.folder_tree(mailbox_id).await?;
                let view = self.mailbox(mailbox_id).await?;
                let calendars = self
                    .container_resources(mailbox_id, DataType::CalendarEvent)
                    .await?;
                let address_books = self
                    .container_resources(mailbox_id, DataType::ContactCard)
                    .await?;
                let rights = Arc::new(DelegateRights::build(
                    tree,
                    self.request.access_token,
                    view.messages.as_deref(),
                    calendars.as_deref(),
                    address_books.as_deref(),
                ));
                self.cache_rights(mailbox_id, rights.clone());
                Ok(ViewRights::Delegate(rights))
            }
        }
    }

    pub(super) async fn container_resources(
        &self,
        mailbox_id: u32,
        data_type: DataType,
    ) -> trc::Result<Option<Arc<GroupwareResources>>> {
        let collection = match data_type {
            DataType::CalendarEvent => SyncCollection::Calendar,
            DataType::ContactCard => SyncCollection::AddressBook,
            _ => return Ok(None),
        };
        if !self.types.contains(data_type) {
            return Ok(None);
        }
        self.request
            .server
            .fetch_groupware_resources(mailbox_id, mailbox_id, collection)
            .await
            .map(Some)
    }

    pub async fn folder_rights(
        &mut self,
        mailbox_id: u32,
        node: FolderNode,
    ) -> trc::Result<FolderRights> {
        Ok(self.view_rights(mailbox_id).await?.of(node))
    }

    pub async fn require_visible(
        &mut self,
        mailbox_id: u32,
        node: FolderNode,
    ) -> Result<(), RopError> {
        if self.folder_rights(mailbox_id, node).await?.is_visible() {
            Ok(())
        } else {
            Err(RopError::Code(ErrorCode::NOT_FOUND))
        }
    }

    pub async fn require_folder_items(
        &mut self,
        mailbox_id: u32,
        folder: u64,
    ) -> Result<(), RopError> {
        if self.request.access_token.is_account_id(mailbox_id) {
            return Ok(());
        }
        let node = MapiId::from_counter(folder)
            .and_then(MapiId::to_node)
            .ok_or(ErrorCode::NOT_FOUND)?;
        self.require_items(mailbox_id, node).await
    }

    pub async fn require_items(
        &mut self,
        mailbox_id: u32,
        node: FolderNode,
    ) -> Result<(), RopError> {
        if self.folder_rights(mailbox_id, node).await?.reads_items() {
            Ok(())
        } else {
            Err(RopError::Code(ErrorCode::ACCESS_DENIED))
        }
    }
}

#[cfg(all(test, stalwart_tests))]
#[rustfmt::skip]
#[path = "../../../../../../stalwart-tests/unit/exchange/src/mapi/emsmdb/access/tests.rs"]
mod tests;
