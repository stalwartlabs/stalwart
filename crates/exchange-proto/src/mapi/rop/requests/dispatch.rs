/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{ics::*, manual, manual::*, props::*, store::*, stub, stubs, tables::*};
use crate::{
    common::LeReader,
    mapi::rop::{
        buffer::DecodeContext,
        error::RopDecodeError,
        header::{RopHeader, RopId},
    },
};

#[derive(Debug, Clone, PartialEq)]
pub enum RopRequest<'a> {
    Release,
    OpenFolder(OpenFolder),
    OpenMessage(OpenMessage),
    GetHierarchyTable(GetHierarchyTable),
    GetContentsTable(GetContentsTable),
    CreateMessage(CreateMessage),
    GetPropertiesSpecific(GetPropertiesSpecific<'a>),
    GetPropertiesAll(GetPropertiesAll),
    GetPropertiesList,
    SetProperties(SetProperties<'a>),
    DeleteProperties(DeleteProperties<'a>),
    SaveChangesMessage(SaveChangesMessage),
    RemoveAllRecipients(RemoveAllRecipients),
    ModifyRecipients(ModifyRecipients<'a>),
    ReadRecipients(ReadRecipients),
    ReloadCachedInformation,
    SetMessageReadFlag(SetMessageReadFlag),
    SetColumns(SetColumns<'a>),
    SortTable(SortTable<'a>),
    Restrict(Restrict<'a>),
    QueryRows(QueryRows),
    QueryPosition,
    SeekRow(SeekRow),
    SeekRowBookmark(SeekRowBookmark<'a>),
    SeekRowFractional(SeekRowFractional),
    CreateBookmark,
    CreateFolder(CreateFolder<'a>),
    DeleteFolder(DeleteFolder),
    DeleteMessages(DeleteMessages<'a>),
    GetMessageStatus(GetMessageStatus),
    SetMessageStatus(SetMessageStatus),
    GetAttachmentTable(GetAttachmentTable),
    OpenAttachment(OpenAttachment),
    CreateAttachment(CreateAttachment),
    DeleteAttachment(DeleteAttachment),
    SaveChangesAttachment(SaveChangesAttachment),
    SetReceiveFolder(SetReceiveFolder<'a>),
    GetReceiveFolder(GetReceiveFolder<'a>),
    RegisterNotification(RegisterNotification),
    OpenStream(OpenStream),
    ReadStream(ReadStream),
    WriteStream(WriteStream<'a>),
    WriteStreamExtended(WriteStream<'a>),
    CopyProperties(CopyProperties<'a>),
    CopyTo(CopyTo<'a>),
    CopyToStream(CopyToStream),
    QueryNamedProperties(QueryNamedProperties),
    SeekStream(SeekStream),
    SetStreamSize(SetStreamSize),
    SetSearchCriteria(SetSearchCriteria<'a>),
    GetSearchCriteria(GetSearchCriteria),
    SubmitMessage(SubmitMessage),
    MoveCopyMessages(MoveCopyMessages<'a>),
    MoveFolder(MoveFolder<'a>),
    CopyFolder(CopyFolder<'a>),
    GetPermissionsTable(GetPermissionsTable),
    GetRulesTable(GetRulesTable),
    ModifyPermissions(ModifyPermissions<'a>),
    ModifyRules(ModifyRules<'a>),
    LongTermIdFromId(LongTermIdFromId),
    IdFromLongTermId(IdFromLongTermId),
    PublicFolderIsGhosted(PublicFolderIsGhosted),
    OpenEmbeddedMessage(OpenEmbeddedMessage),
    GetAddressTypes,
    FastTransferSourceCopyMessages(FastTransferSourceCopyMessages<'a>),
    FastTransferSourceCopyFolder(FastTransferSourceCopyFolder),
    FastTransferSourceCopyTo(FastTransferSourceCopyTo<'a>),
    FastTransferSourceGetBuffer(FastTransferSourceGetBuffer),
    FindRow(FindRow<'a>),
    FastTransferDestinationConfigure(FastTransferDestinationConfigure),
    FastTransferDestinationPutBuffer(FastTransferDestinationPutBuffer<'a>),
    FastTransferDestinationPutBufferExtended(FastTransferDestinationPutBuffer<'a>),
    GetNamesFromPropertyIds(GetNamesFromPropertyIds<'a>),
    GetPropertyIdsFromNames(GetPropertyIdsFromNames<'a>),
    EmptyFolder(EmptyFolder),
    ExpandRow(ExpandRow),
    CollapseRow(CollapseRow),
    CommitStream,
    GetStreamSize,
    SetReadFlags(SetReadFlags<'a>),
    GetReceiveFolderTable,
    FastTransferSourceCopyProperties(FastTransferSourceCopyProperties<'a>),
    GetCollapseState(GetCollapseState),
    SetCollapseState(SetCollapseState<'a>),
    GetTransportFolder,
    SynchronizationConfigure(SynchronizationConfigure<'a>),
    SynchronizationImportMessageChange(SynchronizationImportMessageChange<'a>),
    SynchronizationImportHierarchyChange(SynchronizationImportHierarchyChange<'a>),
    SynchronizationImportDeletes(SynchronizationImportDeletes<'a>),
    SynchronizationUploadStateStreamBegin(SynchronizationUploadStateStreamBegin),
    SynchronizationUploadStateStreamContinue(SynchronizationUploadStateStreamContinue<'a>),
    SynchronizationUploadStateStreamEnd,
    SynchronizationImportMessageMove(SynchronizationImportMessageMove<'a>),
    SynchronizationOpenCollector(SynchronizationOpenCollector),
    GetLocalReplicaIds(GetLocalReplicaIds),
    SynchronizationImportReadStateChanges(SynchronizationImportReadStateChanges<'a>),
    SynchronizationGetTransferState(SynchronizationGetTransferState),
    TellVersion(TellVersion),
    FreeBookmark(FreeBookmark<'a>),
    HardDeleteMessages(HardDeleteMessages<'a>),
    HardDeleteMessagesAndSubfolders(HardDeleteMessagesAndSubfolders),
    Logon(Logon<'a>),
    Stub(RopId, &'a [u8]),
}

pub(crate) fn decode_request<'a>(
    header: &RopHeader,
    r: &mut LeReader<'a>,
    ctx: &DecodeContext<'_>,
) -> Result<RopRequest<'a>, RopDecodeError> {
    match header.id {
        RopId::RELEASE => Ok(RopRequest::Release),
        RopId::OPEN_FOLDER => Ok(RopRequest::OpenFolder(OpenFolder::decode(r, ctx)?)),
        RopId::OPEN_MESSAGE => Ok(RopRequest::OpenMessage(OpenMessage::decode(r, ctx)?)),
        RopId::GET_HIERARCHY_TABLE => Ok(RopRequest::GetHierarchyTable(GetHierarchyTable::decode(
            r, ctx,
        )?)),
        RopId::GET_CONTENTS_TABLE => Ok(RopRequest::GetContentsTable(GetContentsTable::decode(
            r, ctx,
        )?)),
        RopId::CREATE_MESSAGE => Ok(RopRequest::CreateMessage(CreateMessage::decode(r, ctx)?)),
        RopId::GET_PROPERTIES_SPECIFIC => Ok(RopRequest::GetPropertiesSpecific(
            GetPropertiesSpecific::decode(r, ctx)?,
        )),
        RopId::GET_PROPERTIES_ALL => Ok(RopRequest::GetPropertiesAll(GetPropertiesAll::decode(
            r, ctx,
        )?)),
        RopId::GET_PROPERTIES_LIST => Ok(RopRequest::GetPropertiesList),
        RopId::SET_PROPERTIES => Ok(RopRequest::SetProperties(SetProperties::decode(r, ctx)?)),
        RopId::DELETE_PROPERTIES => Ok(RopRequest::DeleteProperties(DeleteProperties::decode(
            r, ctx,
        )?)),
        RopId::SAVE_CHANGES_MESSAGE => Ok(RopRequest::SaveChangesMessage(
            SaveChangesMessage::decode(r, ctx)?,
        )),
        RopId::REMOVE_ALL_RECIPIENTS => Ok(RopRequest::RemoveAllRecipients(
            RemoveAllRecipients::decode(r, ctx)?,
        )),
        RopId::MODIFY_RECIPIENTS => Ok(RopRequest::ModifyRecipients(ModifyRecipients::decode(
            r, ctx,
        )?)),
        RopId::READ_RECIPIENTS => Ok(RopRequest::ReadRecipients(ReadRecipients::decode(r, ctx)?)),
        RopId::RELOAD_CACHED_INFORMATION => {
            r.skip(2)?;
            Ok(RopRequest::ReloadCachedInformation)
        }
        RopId::SET_MESSAGE_READ_FLAG => Ok(RopRequest::SetMessageReadFlag(
            SetMessageReadFlag::decode(r, ctx)?,
        )),
        RopId::SET_COLUMNS => Ok(RopRequest::SetColumns(SetColumns::decode(r, ctx)?)),
        RopId::SORT_TABLE => Ok(RopRequest::SortTable(SortTable::decode(r, ctx)?)),
        RopId::RESTRICT => Ok(RopRequest::Restrict(Restrict::decode(r, ctx)?)),
        RopId::QUERY_ROWS => Ok(RopRequest::QueryRows(QueryRows::decode(r, ctx)?)),
        RopId::GET_STATUS => Ok(RopRequest::Stub(header.id, &[])),
        RopId::QUERY_POSITION => Ok(RopRequest::QueryPosition),
        RopId::SEEK_ROW => Ok(RopRequest::SeekRow(SeekRow::decode(r, ctx)?)),
        RopId::SEEK_ROW_BOOKMARK => Ok(RopRequest::SeekRowBookmark(SeekRowBookmark::decode(
            r, ctx,
        )?)),
        RopId::SEEK_ROW_FRACTIONAL => Ok(RopRequest::SeekRowFractional(SeekRowFractional::decode(
            r, ctx,
        )?)),
        RopId::CREATE_BOOKMARK => Ok(RopRequest::CreateBookmark),
        RopId::CREATE_FOLDER => Ok(RopRequest::CreateFolder(CreateFolder::decode(r, ctx)?)),
        RopId::DELETE_FOLDER => Ok(RopRequest::DeleteFolder(DeleteFolder::decode(r, ctx)?)),
        RopId::DELETE_MESSAGES => Ok(RopRequest::DeleteMessages(DeleteMessages::decode(r, ctx)?)),
        RopId::GET_MESSAGE_STATUS => Ok(RopRequest::GetMessageStatus(GetMessageStatus::decode(
            r, ctx,
        )?)),
        RopId::SET_MESSAGE_STATUS => Ok(RopRequest::SetMessageStatus(SetMessageStatus::decode(
            r, ctx,
        )?)),
        RopId::GET_ATTACHMENT_TABLE => Ok(RopRequest::GetAttachmentTable(
            GetAttachmentTable::decode(r, ctx)?,
        )),
        RopId::OPEN_ATTACHMENT => Ok(RopRequest::OpenAttachment(OpenAttachment::decode(r, ctx)?)),
        RopId::CREATE_ATTACHMENT => Ok(RopRequest::CreateAttachment(CreateAttachment::decode(
            r, ctx,
        )?)),
        RopId::DELETE_ATTACHMENT => Ok(RopRequest::DeleteAttachment(DeleteAttachment::decode(
            r, ctx,
        )?)),
        RopId::SAVE_CHANGES_ATTACHMENT => Ok(RopRequest::SaveChangesAttachment(
            SaveChangesAttachment::decode(r, ctx)?,
        )),
        RopId::SET_RECEIVE_FOLDER => Ok(RopRequest::SetReceiveFolder(SetReceiveFolder::decode(
            r, ctx,
        )?)),
        RopId::GET_RECEIVE_FOLDER => Ok(RopRequest::GetReceiveFolder(GetReceiveFolder::decode(
            r, ctx,
        )?)),
        RopId::REGISTER_NOTIFICATION => Ok(RopRequest::RegisterNotification(
            RegisterNotification::decode(r, ctx)?,
        )),
        RopId::OPEN_STREAM => Ok(RopRequest::OpenStream(OpenStream::decode(r, ctx)?)),
        RopId::READ_STREAM => Ok(RopRequest::ReadStream(ReadStream::decode(r, ctx)?)),
        RopId::WRITE_STREAM => Ok(RopRequest::WriteStream(WriteStream::decode(r, ctx)?)),
        RopId::WRITE_STREAM_EXTENDED => Ok(RopRequest::WriteStreamExtended(WriteStream::decode(
            r, ctx,
        )?)),
        RopId::SEEK_STREAM => Ok(RopRequest::SeekStream(SeekStream::decode(r, ctx)?)),
        RopId::SET_STREAM_SIZE => Ok(RopRequest::SetStreamSize(SetStreamSize::decode(r, ctx)?)),
        RopId::SET_SEARCH_CRITERIA => Ok(RopRequest::SetSearchCriteria(SetSearchCriteria::decode(
            r, ctx,
        )?)),
        RopId::GET_SEARCH_CRITERIA => Ok(RopRequest::GetSearchCriteria(GetSearchCriteria::decode(
            r, ctx,
        )?)),
        RopId::SUBMIT_MESSAGE => Ok(RopRequest::SubmitMessage(SubmitMessage::decode(r, ctx)?)),
        RopId::MOVE_COPY_MESSAGES => Ok(RopRequest::MoveCopyMessages(MoveCopyMessages::decode(
            r, ctx,
        )?)),
        RopId::ABORT_SUBMIT => stub(header.id, r, ctx, stubs::skip_abort_submit),
        RopId::MOVE_FOLDER => Ok(RopRequest::MoveFolder(MoveFolder::decode(r, ctx)?)),
        RopId::COPY_FOLDER => Ok(RopRequest::CopyFolder(CopyFolder::decode(r, ctx)?)),
        RopId::QUERY_COLUMNS_ALL => Ok(RopRequest::Stub(header.id, &[])),
        RopId::ABORT => Ok(RopRequest::Stub(header.id, &[])),
        RopId::COPY_TO => Ok(RopRequest::CopyTo(CopyTo::decode(r, ctx)?)),
        RopId::COPY_TO_STREAM => Ok(RopRequest::CopyToStream(CopyToStream::decode(r, ctx)?)),
        RopId::CLONE_STREAM => stub(header.id, r, ctx, stubs::skip_clone_stream),
        RopId::GET_PERMISSIONS_TABLE => Ok(RopRequest::GetPermissionsTable(
            GetPermissionsTable::decode(r, ctx)?,
        )),
        RopId::GET_RULES_TABLE => Ok(RopRequest::GetRulesTable(GetRulesTable::decode(r, ctx)?)),
        RopId::MODIFY_PERMISSIONS => Ok(RopRequest::ModifyPermissions(ModifyPermissions::decode(
            r, ctx,
        )?)),
        RopId::MODIFY_RULES => Ok(RopRequest::ModifyRules(ModifyRules::decode(r, ctx)?)),
        RopId::GET_OWNING_SERVERS => stub(header.id, r, ctx, stubs::skip_get_owning_servers),
        RopId::LONG_TERM_ID_FROM_ID => Ok(RopRequest::LongTermIdFromId(LongTermIdFromId::decode(
            r, ctx,
        )?)),
        RopId::ID_FROM_LONG_TERM_ID => Ok(RopRequest::IdFromLongTermId(IdFromLongTermId::decode(
            r, ctx,
        )?)),
        RopId::PUBLIC_FOLDER_IS_GHOSTED => Ok(RopRequest::PublicFolderIsGhosted(
            PublicFolderIsGhosted::decode(r, ctx)?,
        )),
        RopId::OPEN_EMBEDDED_MESSAGE => Ok(RopRequest::OpenEmbeddedMessage(
            OpenEmbeddedMessage::decode(r, ctx)?,
        )),
        RopId::SET_SPOOLER => Ok(RopRequest::Stub(header.id, &[])),
        RopId::SPOOLER_LOCK_MESSAGE => stub(header.id, r, ctx, stubs::skip_spooler_lock_message),
        RopId::GET_ADDRESS_TYPES => Ok(RopRequest::GetAddressTypes),
        RopId::TRANSPORT_SEND => Ok(RopRequest::Stub(header.id, &[])),
        RopId::FAST_TRANSFER_SOURCE_COPY_MESSAGES => {
            Ok(RopRequest::FastTransferSourceCopyMessages(
                FastTransferSourceCopyMessages::decode(r, ctx)?,
            ))
        }
        RopId::FAST_TRANSFER_SOURCE_COPY_FOLDER => Ok(RopRequest::FastTransferSourceCopyFolder(
            FastTransferSourceCopyFolder::decode(r, ctx)?,
        )),
        RopId::FAST_TRANSFER_SOURCE_COPY_TO => Ok(RopRequest::FastTransferSourceCopyTo(
            FastTransferSourceCopyTo::decode(r, ctx)?,
        )),
        RopId::FAST_TRANSFER_SOURCE_GET_BUFFER => Ok(RopRequest::FastTransferSourceGetBuffer(
            FastTransferSourceGetBuffer::decode(r, ctx)?,
        )),
        RopId::FIND_ROW => Ok(RopRequest::FindRow(FindRow::decode(r, ctx)?)),
        RopId::PROGRESS => stub(header.id, r, ctx, stubs::skip_progress),
        RopId::TRANSPORT_NEW_MAIL => stub(header.id, r, ctx, stubs::skip_transport_new_mail),
        RopId::GET_VALID_ATTACHMENTS => Ok(RopRequest::Stub(header.id, &[])),
        RopId::FAST_TRANSFER_DESTINATION_CONFIGURE => {
            Ok(RopRequest::FastTransferDestinationConfigure(
                FastTransferDestinationConfigure::decode(r, ctx)?,
            ))
        }
        RopId::FAST_TRANSFER_DESTINATION_PUT_BUFFER => {
            Ok(RopRequest::FastTransferDestinationPutBuffer(
                FastTransferDestinationPutBuffer::decode(r, ctx)?,
            ))
        }
        RopId::FAST_TRANSFER_DESTINATION_PUT_BUFFER_EXTENDED => {
            Ok(RopRequest::FastTransferDestinationPutBufferExtended(
                FastTransferDestinationPutBuffer::decode(r, ctx)?,
            ))
        }
        RopId::GET_NAMES_FROM_PROPERTY_IDS => Ok(RopRequest::GetNamesFromPropertyIds(
            GetNamesFromPropertyIds::decode(r, ctx)?,
        )),
        RopId::GET_PROPERTY_IDS_FROM_NAMES => Ok(RopRequest::GetPropertyIdsFromNames(
            GetPropertyIdsFromNames::decode(r, ctx)?,
        )),
        RopId::UPDATE_DEFERRED_ACTION_MESSAGES => stub(
            header.id,
            r,
            ctx,
            stubs::skip_update_deferred_action_messages,
        ),
        RopId::EMPTY_FOLDER => Ok(RopRequest::EmptyFolder(EmptyFolder::decode(r, ctx)?)),
        RopId::EXPAND_ROW => Ok(RopRequest::ExpandRow(ExpandRow::decode(r, ctx)?)),
        RopId::COLLAPSE_ROW => Ok(RopRequest::CollapseRow(CollapseRow::decode(r, ctx)?)),
        RopId::LOCK_REGION_STREAM => stub(header.id, r, ctx, stubs::skip_lock_region_stream),
        RopId::UNLOCK_REGION_STREAM => stub(header.id, r, ctx, stubs::skip_unlock_region_stream),
        RopId::COMMIT_STREAM => Ok(RopRequest::CommitStream),
        RopId::GET_STREAM_SIZE => Ok(RopRequest::GetStreamSize),
        RopId::QUERY_NAMED_PROPERTIES => Ok(RopRequest::QueryNamedProperties(
            QueryNamedProperties::decode(r, ctx)?,
        )),
        RopId::GET_PER_USER_LONG_TERM_IDS => {
            stub(header.id, r, ctx, stubs::skip_get_per_user_long_term_ids)
        }
        RopId::GET_PER_USER_GUID => stub(header.id, r, ctx, stubs::skip_get_per_user_guid),
        RopId::READ_PER_USER_INFORMATION => {
            stub(header.id, r, ctx, stubs::skip_read_per_user_information)
        }
        RopId::WRITE_PER_USER_INFORMATION => {
            stub(header.id, r, ctx, manual::skip_write_per_user_information)
        }
        RopId::SET_READ_FLAGS => Ok(RopRequest::SetReadFlags(SetReadFlags::decode(r, ctx)?)),
        RopId::COPY_PROPERTIES => Ok(RopRequest::CopyProperties(CopyProperties::decode(r, ctx)?)),
        RopId::GET_RECEIVE_FOLDER_TABLE => Ok(RopRequest::GetReceiveFolderTable),
        RopId::FAST_TRANSFER_SOURCE_COPY_PROPERTIES => {
            Ok(RopRequest::FastTransferSourceCopyProperties(
                FastTransferSourceCopyProperties::decode(r, ctx)?,
            ))
        }
        RopId::GET_COLLAPSE_STATE => Ok(RopRequest::GetCollapseState(GetCollapseState::decode(
            r, ctx,
        )?)),
        RopId::SET_COLLAPSE_STATE => Ok(RopRequest::SetCollapseState(SetCollapseState::decode(
            r, ctx,
        )?)),
        RopId::GET_TRANSPORT_FOLDER => Ok(RopRequest::GetTransportFolder),
        RopId::OPTIONS_DATA => stub(header.id, r, ctx, stubs::skip_options_data),
        RopId::SYNCHRONIZATION_CONFIGURE => Ok(RopRequest::SynchronizationConfigure(
            SynchronizationConfigure::decode(r, ctx)?,
        )),
        RopId::SYNCHRONIZATION_IMPORT_MESSAGE_CHANGE => {
            Ok(RopRequest::SynchronizationImportMessageChange(
                SynchronizationImportMessageChange::decode(r, ctx)?,
            ))
        }
        RopId::SYNCHRONIZATION_IMPORT_HIERARCHY_CHANGE => {
            Ok(RopRequest::SynchronizationImportHierarchyChange(
                SynchronizationImportHierarchyChange::decode(r, ctx)?,
            ))
        }
        RopId::SYNCHRONIZATION_IMPORT_DELETES => Ok(RopRequest::SynchronizationImportDeletes(
            SynchronizationImportDeletes::decode(r, ctx)?,
        )),
        RopId::SYNCHRONIZATION_UPLOAD_STATE_STREAM_BEGIN => {
            Ok(RopRequest::SynchronizationUploadStateStreamBegin(
                SynchronizationUploadStateStreamBegin::decode(r, ctx)?,
            ))
        }
        RopId::SYNCHRONIZATION_UPLOAD_STATE_STREAM_CONTINUE => {
            Ok(RopRequest::SynchronizationUploadStateStreamContinue(
                SynchronizationUploadStateStreamContinue::decode(r, ctx)?,
            ))
        }
        RopId::SYNCHRONIZATION_UPLOAD_STATE_STREAM_END => {
            Ok(RopRequest::SynchronizationUploadStateStreamEnd)
        }
        RopId::SYNCHRONIZATION_IMPORT_MESSAGE_MOVE => {
            Ok(RopRequest::SynchronizationImportMessageMove(
                SynchronizationImportMessageMove::decode(r, ctx)?,
            ))
        }
        RopId::SET_PROPERTIES_NO_REPLICATE => {
            Ok(RopRequest::SetProperties(SetProperties::decode(r, ctx)?))
        }
        RopId::DELETE_PROPERTIES_NO_REPLICATE => Ok(RopRequest::DeleteProperties(
            DeleteProperties::decode(r, ctx)?,
        )),
        RopId::GET_STORE_STATE => Ok(RopRequest::Stub(header.id, &[])),
        RopId::SYNCHRONIZATION_OPEN_COLLECTOR => Ok(RopRequest::SynchronizationOpenCollector(
            SynchronizationOpenCollector::decode(r, ctx)?,
        )),
        RopId::GET_LOCAL_REPLICA_IDS => Ok(RopRequest::GetLocalReplicaIds(
            GetLocalReplicaIds::decode(r, ctx)?,
        )),
        RopId::SYNCHRONIZATION_IMPORT_READ_STATE_CHANGES => {
            Ok(RopRequest::SynchronizationImportReadStateChanges(
                SynchronizationImportReadStateChanges::decode(r, ctx)?,
            ))
        }
        RopId::RESET_TABLE => Ok(RopRequest::Stub(header.id, &[])),
        RopId::SYNCHRONIZATION_GET_TRANSFER_STATE => {
            Ok(RopRequest::SynchronizationGetTransferState(
                SynchronizationGetTransferState::decode(r, ctx)?,
            ))
        }
        RopId::TELL_VERSION => Ok(RopRequest::TellVersion(TellVersion::decode(r, ctx)?)),
        RopId::FREE_BOOKMARK => Ok(RopRequest::FreeBookmark(FreeBookmark::decode(r, ctx)?)),
        RopId::WRITE_AND_COMMIT_STREAM => {
            stub(header.id, r, ctx, stubs::skip_write_and_commit_stream)
        }
        RopId::HARD_DELETE_MESSAGES => Ok(RopRequest::HardDeleteMessages(
            HardDeleteMessages::decode(r, ctx)?,
        )),
        RopId::HARD_DELETE_MESSAGES_AND_SUBFOLDERS => {
            Ok(RopRequest::HardDeleteMessagesAndSubfolders(
                HardDeleteMessagesAndSubfolders::decode(r, ctx)?,
            ))
        }
        RopId::SET_LOCAL_REPLICA_MIDSET_DELETED => stub(
            header.id,
            r,
            ctx,
            stubs::skip_set_local_replica_midset_deleted,
        ),
        RopId::LOGON => Ok(RopRequest::Logon(Logon::decode(header, r, ctx)?)),
        other => Err(RopDecodeError::UnknownRop(other.0)),
    }
}
