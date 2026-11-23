/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::super::views::PropIdArray;
use super::super::views::PropTagArrayView;
use super::super::views::PropertyNameList;
use super::framed;
use crate::common::{Guid, LeReader};
use crate::mapi::prop::CountWidth;
use crate::mapi::prop::PropTag;
use crate::mapi::prop::TaggedValues;
use crate::mapi::rop::{buffer::DecodeContext, error::RopDecodeError};

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct GetPropertiesSpecific<'a> {
    pub property_size_limit: u16,
    pub want_unicode: bool,
    pub property_tags: PropTagArrayView<'a>,
}

impl<'a> GetPropertiesSpecific<'a> {
    pub(crate) fn decode(
        r: &mut LeReader<'a>,
        _ctx: &DecodeContext<'_>,
    ) -> Result<Self, RopDecodeError> {
        let property_size_limit = r.u16()?;
        let want_unicode = r.u16()? != 0;
        let property_tag_count = r.u16()?;
        let property_tags = PropTagArrayView::decode(r, usize::from(property_tag_count))?;
        Ok(GetPropertiesSpecific {
            property_size_limit,
            want_unicode,
            property_tags,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct GetPropertiesAll {
    pub property_size_limit: u16,
    pub want_unicode: bool,
}

impl GetPropertiesAll {
    pub(crate) fn decode(
        r: &mut LeReader<'_>,
        _ctx: &DecodeContext<'_>,
    ) -> Result<Self, RopDecodeError> {
        let property_size_limit = r.u16()?;
        let want_unicode = r.u16()? != 0;
        Ok(GetPropertiesAll {
            property_size_limit,
            want_unicode,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct SetProperties<'a> {
    pub property_values: TaggedValues<'a>,
}

impl<'a> SetProperties<'a> {
    pub(crate) fn decode(
        r: &mut LeReader<'a>,
        ctx: &DecodeContext<'_>,
    ) -> Result<Self, RopDecodeError> {
        let property_value_size = r.u16()?;
        let frame = r.offset();
        let property_value_count = r.u16()?;
        let property_values = TaggedValues::decode(
            r,
            u32::from(property_value_count),
            CountWidth::Rop,
            ctx.limits,
        )?;
        framed(r, frame, usize::from(property_value_size))?;
        Ok(SetProperties { property_values })
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct DeleteProperties<'a> {
    pub property_tags: PropTagArrayView<'a>,
}

impl<'a> DeleteProperties<'a> {
    pub(crate) fn decode(
        r: &mut LeReader<'a>,
        _ctx: &DecodeContext<'_>,
    ) -> Result<Self, RopDecodeError> {
        let property_tag_count = r.u16()?;
        let property_tags = PropTagArrayView::decode(r, usize::from(property_tag_count))?;
        Ok(DeleteProperties { property_tags })
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct GetAttachmentTable {
    pub output_handle_index: u8,
    pub table_flags: u8,
}

impl GetAttachmentTable {
    pub(crate) fn decode(
        r: &mut LeReader<'_>,
        _ctx: &DecodeContext<'_>,
    ) -> Result<Self, RopDecodeError> {
        let output_handle_index = r.u8()?;
        let table_flags = r.u8()?;
        Ok(GetAttachmentTable {
            output_handle_index,
            table_flags,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct OpenStream {
    pub output_handle_index: u8,
    pub property_tag: PropTag,
    pub open_mode_flags: u8,
}

impl OpenStream {
    pub(crate) fn decode(
        r: &mut LeReader<'_>,
        _ctx: &DecodeContext<'_>,
    ) -> Result<Self, RopDecodeError> {
        let output_handle_index = r.u8()?;
        let property_tag = PropTag(r.u32()?);
        let open_mode_flags = r.u8()?;
        Ok(OpenStream {
            output_handle_index,
            property_tag,
            open_mode_flags,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct WriteStream<'a> {
    pub data: &'a [u8],
}

impl<'a> WriteStream<'a> {
    pub(crate) fn decode(
        r: &mut LeReader<'a>,
        _ctx: &DecodeContext<'_>,
    ) -> Result<Self, RopDecodeError> {
        let data_size = r.u16()?;
        let data = r.bytes(usize::from(data_size))?;
        Ok(WriteStream { data })
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct SeekStream {
    pub origin: u8,
    pub offset: u64,
}

impl SeekStream {
    pub(crate) fn decode(
        r: &mut LeReader<'_>,
        _ctx: &DecodeContext<'_>,
    ) -> Result<Self, RopDecodeError> {
        let origin = r.u8()?;
        let offset = r.u64()?;
        Ok(SeekStream { origin, offset })
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct SetStreamSize {
    pub stream_size: u64,
}

impl SetStreamSize {
    pub(crate) fn decode(
        r: &mut LeReader<'_>,
        _ctx: &DecodeContext<'_>,
    ) -> Result<Self, RopDecodeError> {
        let stream_size = r.u64()?;
        Ok(SetStreamSize { stream_size })
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct SubmitMessage {
    pub submit_flags: u8,
}

impl SubmitMessage {
    pub(crate) fn decode(
        r: &mut LeReader<'_>,
        _ctx: &DecodeContext<'_>,
    ) -> Result<Self, RopDecodeError> {
        let submit_flags = r.u8()?;
        Ok(SubmitMessage { submit_flags })
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct GetNamesFromPropertyIds<'a> {
    pub property_ids: PropIdArray<'a>,
}

impl<'a> GetNamesFromPropertyIds<'a> {
    pub(crate) fn decode(
        r: &mut LeReader<'a>,
        _ctx: &DecodeContext<'_>,
    ) -> Result<Self, RopDecodeError> {
        let property_id_count = r.u16()?;
        let property_ids = PropIdArray::decode(r, usize::from(property_id_count))?;
        Ok(GetNamesFromPropertyIds { property_ids })
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct GetPropertyIdsFromNames<'a> {
    pub flags: u8,
    pub property_names: PropertyNameList<'a>,
}

impl<'a> GetPropertyIdsFromNames<'a> {
    pub(crate) fn decode(
        r: &mut LeReader<'a>,
        ctx: &DecodeContext<'_>,
    ) -> Result<Self, RopDecodeError> {
        let flags = r.u8()?;
        let property_name_count = r.u16()?;
        let property_names =
            PropertyNameList::decode(r, usize::from(property_name_count), ctx.limits)?;
        Ok(GetPropertyIdsFromNames {
            flags,
            property_names,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct CopyProperties<'a> {
    pub dest_handle_index: u8,
    pub want_asynchronous: bool,
    pub copy_flags: u8,
    pub property_tags: PropTagArrayView<'a>,
}

impl<'a> CopyProperties<'a> {
    pub(crate) fn decode(
        r: &mut LeReader<'a>,
        _ctx: &DecodeContext<'_>,
    ) -> Result<Self, RopDecodeError> {
        let dest_handle_index = r.u8()?;
        let want_asynchronous = r.u8()? != 0;
        let copy_flags = r.u8()?;
        let property_tag_count = r.u16()?;
        let property_tags = PropTagArrayView::decode(r, usize::from(property_tag_count))?;
        Ok(CopyProperties {
            dest_handle_index,
            want_asynchronous,
            copy_flags,
            property_tags,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct CopyTo<'a> {
    pub dest_handle_index: u8,
    pub want_asynchronous: bool,
    pub want_sub_objects: bool,
    pub copy_flags: u8,
    pub excluded_tags: PropTagArrayView<'a>,
}

impl<'a> CopyTo<'a> {
    pub(crate) fn decode(
        r: &mut LeReader<'a>,
        _ctx: &DecodeContext<'_>,
    ) -> Result<Self, RopDecodeError> {
        let dest_handle_index = r.u8()?;
        let want_asynchronous = r.u8()? != 0;
        let want_sub_objects = r.u8()? != 0;
        let copy_flags = r.u8()?;
        let excluded_tag_count = r.u16()?;
        let excluded_tags = PropTagArrayView::decode(r, usize::from(excluded_tag_count))?;
        Ok(CopyTo {
            dest_handle_index,
            want_asynchronous,
            want_sub_objects,
            copy_flags,
            excluded_tags,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct CopyToStream {
    pub dest_handle_index: u8,
    pub byte_count: u64,
}

impl CopyToStream {
    pub(crate) fn decode(
        r: &mut LeReader<'_>,
        _ctx: &DecodeContext<'_>,
    ) -> Result<Self, RopDecodeError> {
        let dest_handle_index = r.u8()?;
        let byte_count = r.u64()?;
        Ok(CopyToStream {
            dest_handle_index,
            byte_count,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct QueryNamedProperties {
    pub query_flags: u8,
    pub property_guid: Option<Guid>,
}

impl QueryNamedProperties {
    pub const NO_STRINGS: u8 = 0x01;
    pub const NO_IDS: u8 = 0x02;

    pub(crate) fn decode(
        r: &mut LeReader<'_>,
        _ctx: &DecodeContext<'_>,
    ) -> Result<Self, RopDecodeError> {
        let query_flags = r.u8()?;
        let property_guid = if r.u8()? != 0 {
            Some(Guid(r.array()?))
        } else {
            None
        };
        Ok(QueryNamedProperties {
            query_flags,
            property_guid,
        })
    }
}
