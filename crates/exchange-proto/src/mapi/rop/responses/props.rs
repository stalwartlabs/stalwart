/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::PropertyProblem;
use super::TaggedValue;
use crate::common::LeWriter;
use crate::ids::Eid;
use crate::mapi::prop::PropId;
use crate::mapi::prop::PropKeyRef;
use crate::mapi::prop::PropTag;
use crate::mapi::prop::PropertyName;
use crate::mapi::rop::writer::RopResponse;

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct GetPropertiesAllResponse<'x> {
    pub property_values: &'x [TaggedValue<'x>],
}

impl RopResponse for GetPropertiesAllResponse<'_> {
    fn encode(&self, out: &mut Vec<u8>) {
        let property_values_len = u16::try_from(self.property_values.len()).unwrap_or(u16::MAX);
        out.put_u16(property_values_len);
        for item in self
            .property_values
            .iter()
            .take(usize::from(property_values_len))
        {
            item.encode(out);
        }
    }

    fn encoded_len_hint(&self) -> usize {
        2_usize.saturating_add(self.property_values.len().saturating_mul(8))
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct GetPropertiesListResponse<'x> {
    pub property_tags: &'x [PropTag],
}

impl RopResponse for GetPropertiesListResponse<'_> {
    fn encode(&self, out: &mut Vec<u8>) {
        let property_tags_len = u16::try_from(self.property_tags.len()).unwrap_or(u16::MAX);
        out.put_u16(property_tags_len);
        for item in self
            .property_tags
            .iter()
            .take(usize::from(property_tags_len))
        {
            out.put_u32(item.0);
        }
    }

    fn encoded_len_hint(&self) -> usize {
        2_usize.saturating_add(self.property_tags.len().saturating_mul(4))
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct SetPropertiesResponse<'x> {
    pub property_problems: &'x [PropertyProblem],
}

impl RopResponse for SetPropertiesResponse<'_> {
    fn encode(&self, out: &mut Vec<u8>) {
        let property_problems_len = u16::try_from(self.property_problems.len()).unwrap_or(u16::MAX);
        out.put_u16(property_problems_len);
        for item in self
            .property_problems
            .iter()
            .take(usize::from(property_problems_len))
        {
            item.encode(out);
        }
    }

    fn encoded_len_hint(&self) -> usize {
        2_usize.saturating_add(self.property_problems.len().saturating_mul(10))
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct DeletePropertiesResponse<'x> {
    pub property_problems: &'x [PropertyProblem],
}

impl RopResponse for DeletePropertiesResponse<'_> {
    fn encode(&self, out: &mut Vec<u8>) {
        let property_problems_len = u16::try_from(self.property_problems.len()).unwrap_or(u16::MAX);
        out.put_u16(property_problems_len);
        for item in self
            .property_problems
            .iter()
            .take(usize::from(property_problems_len))
        {
            item.encode(out);
        }
    }

    fn encoded_len_hint(&self) -> usize {
        2_usize.saturating_add(self.property_problems.len().saturating_mul(10))
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct OpenStreamResponse {
    pub stream_size: u32,
}

impl RopResponse for OpenStreamResponse {
    fn encode(&self, out: &mut Vec<u8>) {
        out.put_u32(self.stream_size);
    }

    fn encoded_len_hint(&self) -> usize {
        4
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct ReadStreamResponse<'x> {
    pub data: &'x [u8],
}

impl RopResponse for ReadStreamResponse<'_> {
    fn encode(&self, out: &mut Vec<u8>) {
        let data_len = u16::try_from(self.data.len()).unwrap_or(u16::MAX);
        out.put_u16(data_len);
        out.extend_from_slice(self.data.get(..usize::from(data_len)).unwrap_or(self.data));
    }

    fn encoded_len_hint(&self) -> usize {
        2_usize.saturating_add(self.data.len())
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct WriteStreamResponse {
    pub written_size: u16,
}

impl RopResponse for WriteStreamResponse {
    fn encode(&self, out: &mut Vec<u8>) {
        out.put_u16(self.written_size);
    }

    fn encoded_len_hint(&self) -> usize {
        2
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WriteStreamExtendedResponse {
    pub written_size: u32,
}

impl RopResponse for WriteStreamExtendedResponse {
    fn encode(&self, out: &mut Vec<u8>) {
        out.put_u32(self.written_size);
    }

    fn encoded_len_hint(&self) -> usize {
        4
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct SeekStreamResponse {
    pub new_position: u64,
}

impl RopResponse for SeekStreamResponse {
    fn encode(&self, out: &mut Vec<u8>) {
        out.put_u64(self.new_position);
    }

    fn encoded_len_hint(&self) -> usize {
        8
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct GetNamesFromPropertyIdsResponse<'x> {
    pub property_names: &'x [PropKeyRef<'x>],
}

impl RopResponse for GetNamesFromPropertyIdsResponse<'_> {
    fn encode(&self, out: &mut Vec<u8>) {
        let property_names_len = u16::try_from(self.property_names.len()).unwrap_or(u16::MAX);
        out.put_u16(property_names_len);
        for item in self
            .property_names
            .iter()
            .take(usize::from(property_names_len))
        {
            PropertyName::encode_key(*item, out);
        }
    }

    fn encoded_len_hint(&self) -> usize {
        2_usize.saturating_add(self.property_names.len().saturating_mul(24))
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct GetPropertyIdsFromNamesResponse<'x> {
    pub property_ids: &'x [PropId],
}

impl RopResponse for GetPropertyIdsFromNamesResponse<'_> {
    fn encode(&self, out: &mut Vec<u8>) {
        let property_ids_len = u16::try_from(self.property_ids.len()).unwrap_or(u16::MAX);
        out.put_u16(property_ids_len);
        for item in self.property_ids.iter().take(usize::from(property_ids_len)) {
            out.put_u16(item.0);
        }
    }

    fn encoded_len_hint(&self) -> usize {
        2_usize.saturating_add(self.property_ids.len().saturating_mul(2))
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct GetStreamSizeResponse {
    pub stream_size: u32,
}

impl RopResponse for GetStreamSizeResponse {
    fn encode(&self, out: &mut Vec<u8>) {
        out.put_u32(self.stream_size);
    }

    fn encoded_len_hint(&self) -> usize {
        4
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct GetTransportFolderResponse {
    pub folder_id: Eid,
}

impl RopResponse for GetTransportFolderResponse {
    fn encode(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.folder_id.to_wire());
    }

    fn encoded_len_hint(&self) -> usize {
        8
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct QueryNamedPropertiesResponse<'x> {
    pub entries: &'x [(PropId, PropKeyRef<'x>)],
}

impl RopResponse for QueryNamedPropertiesResponse<'_> {
    fn encode(&self, out: &mut Vec<u8>) {
        let id_count = u16::try_from(self.entries.len()).unwrap_or(u16::MAX);
        let entries = self
            .entries
            .get(..usize::from(id_count))
            .unwrap_or_default();
        out.put_u16(id_count);
        for (id, _) in entries {
            out.put_u16(id.0);
        }
        for (_, key) in entries {
            PropertyName::encode_key(*key, out);
        }
    }

    fn encoded_len_hint(&self) -> usize {
        2_usize.saturating_add(self.entries.len().saturating_mul(26))
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct CopyToStreamResponse {
    pub read_byte_count: u64,
    pub written_byte_count: u64,
}

impl RopResponse for CopyToStreamResponse {
    fn encode(&self, out: &mut Vec<u8>) {
        out.put_u64(self.read_byte_count);
        out.put_u64(self.written_byte_count);
    }

    fn encoded_len_hint(&self) -> usize {
        16
    }
}
