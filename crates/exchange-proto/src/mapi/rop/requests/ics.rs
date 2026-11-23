/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::super::views::EidArray;
use super::super::views::MessageReadStates;
use super::super::views::PermissionDataList;
use super::super::views::PropTagArrayView;
use super::super::views::RuleDataList;
use super::too_many;
use crate::common::LeReader;
use crate::ics::flags::FastTransferCopyFlags;
use crate::ics::flags::FastTransferCopyToFlags;
use crate::ics::flags::ImportFlags;
use crate::ics::flags::SendOptions;
use crate::ics::flags::SynchronizationExtraFlags;
use crate::ics::flags::SynchronizationFlags;
use crate::ics::flags::SynchronizationType;
use crate::mapi::prop::CountWidth;
use crate::mapi::prop::PropTag;
use crate::mapi::prop::TaggedValues;
use crate::mapi::restriction::RestrictionBytes;
use crate::mapi::rop::{buffer::DecodeContext, error::RopDecodeError};

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct GetPermissionsTable {
    pub output_handle_index: u8,
    pub table_flags: u8,
}

impl GetPermissionsTable {
    pub(crate) fn decode(
        r: &mut LeReader<'_>,
        _ctx: &DecodeContext<'_>,
    ) -> Result<Self, RopDecodeError> {
        let output_handle_index = r.u8()?;
        let table_flags = r.u8()?;
        Ok(GetPermissionsTable {
            output_handle_index,
            table_flags,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct GetRulesTable {
    pub output_handle_index: u8,
    pub table_flags: u8,
}

impl GetRulesTable {
    pub(crate) fn decode(
        r: &mut LeReader<'_>,
        _ctx: &DecodeContext<'_>,
    ) -> Result<Self, RopDecodeError> {
        let output_handle_index = r.u8()?;
        let table_flags = r.u8()?;
        Ok(GetRulesTable {
            output_handle_index,
            table_flags,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct ModifyPermissions<'a> {
    pub modify_flags: u8,
    pub permissions_data: PermissionDataList<'a>,
}

impl<'a> ModifyPermissions<'a> {
    pub(crate) fn decode(
        r: &mut LeReader<'a>,
        ctx: &DecodeContext<'_>,
    ) -> Result<Self, RopDecodeError> {
        let modify_flags = r.u8()?;
        let modify_count = r.u16()?;
        let permissions_data =
            PermissionDataList::decode(r, usize::from(modify_count), ctx.limits)?;
        Ok(ModifyPermissions {
            modify_flags,
            permissions_data,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct ModifyRules<'a> {
    pub modify_rules_flags: u8,
    pub rules_data: RuleDataList<'a>,
}

impl<'a> ModifyRules<'a> {
    pub(crate) fn decode(
        r: &mut LeReader<'a>,
        ctx: &DecodeContext<'_>,
    ) -> Result<Self, RopDecodeError> {
        let modify_rules_flags = r.u8()?;
        let rules_count = r.u16()?;
        let rules_data = RuleDataList::decode(r, usize::from(rules_count), ctx.limits)?;
        Ok(ModifyRules {
            modify_rules_flags,
            rules_data,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct FastTransferSourceCopyMessages<'a> {
    pub output_handle_index: u8,
    pub message_ids: EidArray<'a>,
    pub copy_flags: FastTransferCopyFlags,
    pub send_options: SendOptions,
}

impl<'a> FastTransferSourceCopyMessages<'a> {
    pub(crate) fn decode(
        r: &mut LeReader<'a>,
        _ctx: &DecodeContext<'_>,
    ) -> Result<Self, RopDecodeError> {
        let output_handle_index = r.u8()?;
        let message_id_count = r.u16()?;
        let message_ids = EidArray::decode(r, usize::from(message_id_count))?;
        let copy_flags = FastTransferCopyFlags(r.u8()?);
        let send_options = SendOptions(r.u8()?);
        Ok(FastTransferSourceCopyMessages {
            output_handle_index,
            message_ids,
            copy_flags,
            send_options,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct FastTransferSourceCopyFolder {
    pub output_handle_index: u8,
    pub copy_flags: FastTransferCopyFlags,
    pub send_options: SendOptions,
}

impl FastTransferSourceCopyFolder {
    pub(crate) fn decode(
        r: &mut LeReader<'_>,
        _ctx: &DecodeContext<'_>,
    ) -> Result<Self, RopDecodeError> {
        let output_handle_index = r.u8()?;
        let copy_flags = FastTransferCopyFlags(r.u8()?);
        let send_options = SendOptions(r.u8()?);
        Ok(FastTransferSourceCopyFolder {
            output_handle_index,
            copy_flags,
            send_options,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct FastTransferSourceCopyTo<'a> {
    pub output_handle_index: u8,
    pub level: u8,
    pub copy_flags: FastTransferCopyToFlags,
    pub send_options: SendOptions,
    pub property_tags: PropTagArrayView<'a>,
}

impl<'a> FastTransferSourceCopyTo<'a> {
    pub(crate) fn decode(
        r: &mut LeReader<'a>,
        _ctx: &DecodeContext<'_>,
    ) -> Result<Self, RopDecodeError> {
        let output_handle_index = r.u8()?;
        let level = r.u8()?;
        let copy_flags = FastTransferCopyToFlags(r.u32()?);
        let send_options = SendOptions(r.u8()?);
        let property_tag_count = r.u16()?;
        let property_tags = PropTagArrayView::decode(r, usize::from(property_tag_count))?;
        Ok(FastTransferSourceCopyTo {
            output_handle_index,
            level,
            copy_flags,
            send_options,
            property_tags,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct FastTransferDestinationConfigure {
    pub output_handle_index: u8,
    pub source_operation: u8,
    pub copy_flags: u8,
}

impl FastTransferDestinationConfigure {
    pub(crate) fn decode(
        r: &mut LeReader<'_>,
        _ctx: &DecodeContext<'_>,
    ) -> Result<Self, RopDecodeError> {
        let output_handle_index = r.u8()?;
        let source_operation = r.u8()?;
        let copy_flags = r.u8()?;
        Ok(FastTransferDestinationConfigure {
            output_handle_index,
            source_operation,
            copy_flags,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct FastTransferDestinationPutBuffer<'a> {
    pub transfer_data: &'a [u8],
}

impl<'a> FastTransferDestinationPutBuffer<'a> {
    pub(crate) fn decode(
        r: &mut LeReader<'a>,
        _ctx: &DecodeContext<'_>,
    ) -> Result<Self, RopDecodeError> {
        let transfer_data_size = r.u16()?;
        let transfer_data = r.bytes(usize::from(transfer_data_size))?;
        Ok(FastTransferDestinationPutBuffer { transfer_data })
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct FastTransferSourceCopyProperties<'a> {
    pub output_handle_index: u8,
    pub level: u8,
    pub copy_flags: FastTransferCopyFlags,
    pub send_options: SendOptions,
    pub property_tags: PropTagArrayView<'a>,
}

impl<'a> FastTransferSourceCopyProperties<'a> {
    pub(crate) fn decode(
        r: &mut LeReader<'a>,
        _ctx: &DecodeContext<'_>,
    ) -> Result<Self, RopDecodeError> {
        let output_handle_index = r.u8()?;
        let level = r.u8()?;
        let copy_flags = FastTransferCopyFlags(r.u8()?);
        let send_options = SendOptions(r.u8()?);
        let property_tag_count = r.u16()?;
        let property_tags = PropTagArrayView::decode(r, usize::from(property_tag_count))?;
        Ok(FastTransferSourceCopyProperties {
            output_handle_index,
            level,
            copy_flags,
            send_options,
            property_tags,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct SynchronizationConfigure<'a> {
    pub output_handle_index: u8,
    pub synchronization_type: Option<SynchronizationType>,
    pub send_options: SendOptions,
    pub synchronization_flags: SynchronizationFlags,
    pub restriction_data: RestrictionBytes<'a>,
    pub synchronization_extra_flags: SynchronizationExtraFlags,
    pub property_tags: PropTagArrayView<'a>,
}

impl<'a> SynchronizationConfigure<'a> {
    pub(crate) fn decode(
        r: &mut LeReader<'a>,
        _ctx: &DecodeContext<'_>,
    ) -> Result<Self, RopDecodeError> {
        let output_handle_index = r.u8()?;
        let synchronization_type = SynchronizationType::from_wire(r.u8()?);
        let send_options = SendOptions(r.u8()?);
        let flags_offset = r.offset();
        let synchronization_flags = SynchronizationFlags(r.u16()?);
        if synchronization_flags.contains(SynchronizationFlags::RESERVED) {
            return Err(RopDecodeError::BadValue {
                offset: RopDecodeError::at(flags_offset),
            });
        }
        let restriction_data_size = r.u16()?;
        let restriction_data = RestrictionBytes(r.bytes(usize::from(restriction_data_size))?);
        let synchronization_extra_flags = SynchronizationExtraFlags(r.u32()?);
        let property_tag_count = r.u16()?;
        let property_tags = PropTagArrayView::decode(r, usize::from(property_tag_count))?;
        Ok(SynchronizationConfigure {
            output_handle_index,
            synchronization_type,
            send_options,
            synchronization_flags,
            restriction_data,
            synchronization_extra_flags,
            property_tags,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct SynchronizationImportMessageChange<'a> {
    pub output_handle_index: u8,
    pub import_flag: ImportFlags,
    pub property_values: TaggedValues<'a>,
}

impl<'a> SynchronizationImportMessageChange<'a> {
    pub(crate) fn decode(
        r: &mut LeReader<'a>,
        ctx: &DecodeContext<'_>,
    ) -> Result<Self, RopDecodeError> {
        let output_handle_index = r.u8()?;
        let import_flag = ImportFlags(r.u8()?);
        let property_value_count = r.u16()?;
        let property_values = TaggedValues::decode(
            r,
            u32::from(property_value_count),
            CountWidth::Rop,
            ctx.limits,
        )?;
        Ok(SynchronizationImportMessageChange {
            output_handle_index,
            import_flag,
            property_values,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct SynchronizationImportHierarchyChange<'a> {
    pub hierarchy_values: TaggedValues<'a>,
    pub property_values: TaggedValues<'a>,
}

impl<'a> SynchronizationImportHierarchyChange<'a> {
    pub(crate) fn decode(
        r: &mut LeReader<'a>,
        ctx: &DecodeContext<'_>,
    ) -> Result<Self, RopDecodeError> {
        let hierarchy_value_count = r.u16()?;
        let hierarchy_values = TaggedValues::decode(
            r,
            u32::from(hierarchy_value_count),
            CountWidth::Rop,
            ctx.limits,
        )?;
        let property_value_count = r.u16()?;
        let property_values = TaggedValues::decode(
            r,
            u32::from(property_value_count),
            CountWidth::Rop,
            ctx.limits,
        )?;
        Ok(SynchronizationImportHierarchyChange {
            hierarchy_values,
            property_values,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct SynchronizationImportDeletes<'a> {
    pub import_delete_flags: u8,
    pub property_values: TaggedValues<'a>,
}

impl<'a> SynchronizationImportDeletes<'a> {
    pub(crate) fn decode(
        r: &mut LeReader<'a>,
        ctx: &DecodeContext<'_>,
    ) -> Result<Self, RopDecodeError> {
        let import_delete_flags = r.u8()?;
        let property_value_count = r.u16()?;
        let property_values = TaggedValues::decode(
            r,
            u32::from(property_value_count),
            CountWidth::Rop,
            ctx.limits,
        )?;
        Ok(SynchronizationImportDeletes {
            import_delete_flags,
            property_values,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct SynchronizationUploadStateStreamBegin {
    pub state_property: PropTag,
    pub transfer_buffer_size: u32,
}

impl SynchronizationUploadStateStreamBegin {
    pub(crate) fn decode(
        r: &mut LeReader<'_>,
        _ctx: &DecodeContext<'_>,
    ) -> Result<Self, RopDecodeError> {
        let state_property = PropTag(r.u32()?);
        let transfer_buffer_size = r.u32()?;
        Ok(SynchronizationUploadStateStreamBegin {
            state_property,
            transfer_buffer_size,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct SynchronizationUploadStateStreamContinue<'a> {
    pub stream_data: &'a [u8],
}

impl<'a> SynchronizationUploadStateStreamContinue<'a> {
    pub(crate) fn decode(
        r: &mut LeReader<'a>,
        _ctx: &DecodeContext<'_>,
    ) -> Result<Self, RopDecodeError> {
        let stream_data_size = r.u32()?;
        let stream_data = r.bytes(usize::try_from(stream_data_size).map_err(|_| too_many(r))?)?;
        Ok(SynchronizationUploadStateStreamContinue { stream_data })
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct SynchronizationImportMessageMove<'a> {
    pub source_folder_id: &'a [u8],
    pub source_message_id: &'a [u8],
    pub predecessor_change_list: &'a [u8],
    pub destination_message_id: &'a [u8],
    pub change_number: &'a [u8],
}

impl<'a> SynchronizationImportMessageMove<'a> {
    pub(crate) fn decode(
        r: &mut LeReader<'a>,
        _ctx: &DecodeContext<'_>,
    ) -> Result<Self, RopDecodeError> {
        let source_folder_id_size = r.u32()?;
        let source_folder_id =
            r.bytes(usize::try_from(source_folder_id_size).map_err(|_| too_many(r))?)?;
        let source_message_id_size = r.u32()?;
        let source_message_id =
            r.bytes(usize::try_from(source_message_id_size).map_err(|_| too_many(r))?)?;
        let predecessor_change_list_size = r.u32()?;
        let predecessor_change_list =
            r.bytes(usize::try_from(predecessor_change_list_size).map_err(|_| too_many(r))?)?;
        let destination_message_id_size = r.u32()?;
        let destination_message_id =
            r.bytes(usize::try_from(destination_message_id_size).map_err(|_| too_many(r))?)?;
        let change_number_size = r.u32()?;
        let change_number =
            r.bytes(usize::try_from(change_number_size).map_err(|_| too_many(r))?)?;
        Ok(SynchronizationImportMessageMove {
            source_folder_id,
            source_message_id,
            predecessor_change_list,
            destination_message_id,
            change_number,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct SynchronizationOpenCollector {
    pub output_handle_index: u8,
    pub is_contents_collector: bool,
}

impl SynchronizationOpenCollector {
    pub(crate) fn decode(
        r: &mut LeReader<'_>,
        _ctx: &DecodeContext<'_>,
    ) -> Result<Self, RopDecodeError> {
        let output_handle_index = r.u8()?;
        let is_contents_collector = r.u8()? != 0;
        Ok(SynchronizationOpenCollector {
            output_handle_index,
            is_contents_collector,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct GetLocalReplicaIds {
    pub id_count: u32,
}

impl GetLocalReplicaIds {
    pub(crate) fn decode(
        r: &mut LeReader<'_>,
        _ctx: &DecodeContext<'_>,
    ) -> Result<Self, RopDecodeError> {
        let id_count = r.u32()?;
        Ok(GetLocalReplicaIds { id_count })
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct SynchronizationImportReadStateChanges<'a> {
    pub message_read_states: MessageReadStates<'a>,
}

impl<'a> SynchronizationImportReadStateChanges<'a> {
    pub(crate) fn decode(
        r: &mut LeReader<'a>,
        _ctx: &DecodeContext<'_>,
    ) -> Result<Self, RopDecodeError> {
        let message_read_states_size = r.u16()?;
        let message_read_states =
            MessageReadStates::decode(r.bytes(usize::from(message_read_states_size))?)?;
        Ok(SynchronizationImportReadStateChanges {
            message_read_states,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct SynchronizationGetTransferState {
    pub output_handle_index: u8,
}

impl SynchronizationGetTransferState {
    pub(crate) fn decode(
        r: &mut LeReader<'_>,
        _ctx: &DecodeContext<'_>,
    ) -> Result<Self, RopDecodeError> {
        let output_handle_index = r.u8()?;
        Ok(SynchronizationGetTransferState {
            output_handle_index,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct TellVersion {
    pub version: [u8; 6],
}

impl TellVersion {
    pub(crate) fn decode(
        r: &mut LeReader<'_>,
        _ctx: &DecodeContext<'_>,
    ) -> Result<Self, RopDecodeError> {
        let version = r.array()?;
        Ok(TellVersion { version })
    }
}
