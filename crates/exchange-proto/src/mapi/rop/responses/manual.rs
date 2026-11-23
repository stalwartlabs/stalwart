/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::num::NonZeroU16;

use crate::{
    common::{Guid, LeWriter},
    ics::flags::TransferStatus,
    ids::{Eid, Fid, ReplGuid, ReplId},
    mapi::{
        prop::{
            CodePage, PropTag,
            row::{CellLimit, RowOptions, RowStrings},
        },
        recipient::RecipientRow,
        rop::writer::RopResponse,
    },
};

pub const SPECIAL_FOLDER_COUNT: usize = 13;
const TRANSFER_BUFFER_MAX: usize = u16::MAX as usize;
const RECIPIENT_ROW_HINT: usize = 64;

pub fn table_row_options(unicode: bool, code_page: CodePage) -> RowOptions {
    RowOptions {
        strings: if unicode {
            RowStrings::Unicode
        } else {
            RowStrings::String8
        },
        cell_limit: CellLimit::Table,
        code_page,
    }
}

pub fn property_row_options(
    want_unicode: bool,
    property_size_limit: u16,
    code_page: CodePage,
) -> RowOptions {
    RowOptions {
        strings: if want_unicode {
            RowStrings::Unicode
        } else {
            RowStrings::String8
        },
        cell_limit: CellLimit::Property {
            size_limit: NonZeroU16::new(property_size_limit),
        },
        code_page,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LogonTime {
    pub seconds: u8,
    pub minutes: u8,
    pub hour: u8,
    pub day_of_week: u8,
    pub day: u8,
    pub month: u8,
    pub year: u16,
}

impl LogonTime {
    fn encode(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&[
            self.seconds,
            self.minutes,
            self.hour,
            self.day_of_week,
            self.day,
            self.month,
        ]);
        out.put_u16(self.year);
    }
}

fn put_folder_ids(out: &mut Vec<u8>, folder_ids: &[Fid; SPECIAL_FOLDER_COUNT]) {
    for fid in folder_ids {
        out.extend_from_slice(&fid.to_wire());
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LogonPrivateResponse {
    pub logon_flags: u8,
    pub folder_ids: [Fid; SPECIAL_FOLDER_COUNT],
    pub response_flags: u8,
    pub mailbox_guid: Guid,
    pub repl_id: ReplId,
    pub repl_guid: ReplGuid,
    pub logon_time: LogonTime,
    pub gwart_time: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LogonPublicResponse {
    pub logon_flags: u8,
    pub folder_ids: [Fid; SPECIAL_FOLDER_COUNT],
    pub repl_id: ReplId,
    pub repl_guid: ReplGuid,
    pub per_user_guid: Guid,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogonResponse {
    Private(LogonPrivateResponse),
    Public(LogonPublicResponse),
}

impl RopResponse for LogonResponse {
    fn encode(&self, out: &mut Vec<u8>) {
        match self {
            LogonResponse::Private(r) => {
                out.put_u8(r.logon_flags);
                put_folder_ids(out, &r.folder_ids);
                out.put_u8(r.response_flags);
                out.put_guid(&r.mailbox_guid);
                out.put_u16(r.repl_id.0);
                out.put_guid(&r.repl_guid.0);
                r.logon_time.encode(out);
                out.put_u64(r.gwart_time);
                out.put_u32(0);
            }
            LogonResponse::Public(r) => {
                out.put_u8(r.logon_flags);
                put_folder_ids(out, &r.folder_ids);
                out.put_u16(r.repl_id.0);
                out.put_guid(&r.repl_guid.0);
                out.put_guid(&r.per_user_guid);
            }
        }
    }

    fn encoded_len_hint(&self) -> usize {
        match self {
            LogonResponse::Private(_) => 160,
            LogonResponse::Public(_) => 139,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GhostedServers<'x> {
    pub cheap_server_count: u16,
    pub servers: &'x [&'x [u8]],
}

impl GhostedServers<'_> {
    fn encode(&self, out: &mut Vec<u8>) {
        let count = u16::try_from(self.servers.len()).unwrap_or(u16::MAX);
        out.put_u16(count);
        out.put_u16(self.cheap_server_count.min(count));
        for server in self.servers.iter().take(usize::from(count)) {
            out.put_ascii_z(server);
        }
    }

    fn len_hint(&self) -> usize {
        self.servers
            .iter()
            .fold(4, |acc, s| acc.saturating_add(s.len()).saturating_add(1))
    }
}

fn put_ghosted(out: &mut Vec<u8>, ghosted: &Option<GhostedServers<'_>>) {
    out.put_u8(u8::from(ghosted.is_some()));
    if let Some(ghosted) = ghosted {
        ghosted.encode(out);
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OpenFolderResponse<'x> {
    pub has_rules: bool,
    pub ghosted: Option<GhostedServers<'x>>,
}

impl RopResponse for OpenFolderResponse<'_> {
    fn encode(&self, out: &mut Vec<u8>) {
        out.put_u8(u8::from(self.has_rules));
        put_ghosted(out, &self.ghosted);
    }

    fn encoded_len_hint(&self) -> usize {
        2_usize.saturating_add(self.ghosted.map_or(0, |g| g.len_hint()))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExistingFolder<'x> {
    pub has_rules: bool,
    pub ghosted: Option<GhostedServers<'x>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CreateFolderResponse<'x> {
    pub folder_id: Eid,
    pub existing: Option<ExistingFolder<'x>>,
}

impl RopResponse for CreateFolderResponse<'_> {
    fn encode(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.folder_id.to_wire());
        out.put_u8(u8::from(self.existing.is_some()));
        if let Some(existing) = &self.existing {
            out.put_u8(u8::from(existing.has_rules));
            put_ghosted(out, &existing.ghosted);
        }
    }

    fn encoded_len_hint(&self) -> usize {
        11_usize.saturating_add(
            self.existing
                .and_then(|e| e.ghosted)
                .map_or(0, |g| g.len_hint()),
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReadStatusChange {
    pub logon_id: u8,
    pub client_data: [u8; 24],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SetMessageReadFlagResponse {
    pub changed: Option<ReadStatusChange>,
}

impl RopResponse for SetMessageReadFlagResponse {
    fn encode(&self, out: &mut Vec<u8>) {
        out.put_u8(u8::from(self.changed.is_some()));
        if let Some(changed) = &self.changed {
            out.put_u8(changed.logon_id);
            out.extend_from_slice(&changed.client_data);
        }
    }

    fn encoded_len_hint(&self) -> usize {
        26
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TypedString<'x> {
    Absent,
    Empty,
    String8(&'x [u8]),
    ReducedUnicode(&'x [u8]),
    Unicode(&'x str),
}

impl<'x> TypedString<'x> {
    const ABSENT: u8 = 0x00;
    const EMPTY: u8 = 0x01;
    const STRING8: u8 = 0x02;
    const REDUCED: u8 = 0x03;
    const UNICODE: u8 = 0x04;

    pub fn from_text(text: Option<&'x str>) -> Self {
        match text {
            None => TypedString::Absent,
            Some("") => TypedString::Empty,
            Some(text) if text.is_ascii() => TypedString::ReducedUnicode(text.as_bytes()),
            Some(text) => TypedString::Unicode(text),
        }
    }

    fn encode(&self, out: &mut Vec<u8>) {
        match self {
            TypedString::Absent => out.put_u8(Self::ABSENT),
            TypedString::Empty => out.put_u8(Self::EMPTY),
            TypedString::String8(bytes) => {
                out.put_u8(Self::STRING8);
                out.put_ascii_z(bytes);
            }
            TypedString::ReducedUnicode(bytes) => {
                out.put_u8(Self::REDUCED);
                out.put_ascii_z(bytes);
            }
            TypedString::Unicode(text) => {
                out.put_u8(Self::UNICODE);
                out.put_utf16_z(text);
            }
        }
    }

    fn len_hint(&self) -> usize {
        match self {
            TypedString::Absent | TypedString::Empty => 1,
            TypedString::String8(b) | TypedString::ReducedUnicode(b) => b.len().saturating_add(2),
            TypedString::Unicode(t) => t.len().saturating_mul(2).saturating_add(3),
        }
    }
}

fn put_sized_recipient(out: &mut Vec<u8>, row: &RecipientRow<'_>, code_page: CodePage) {
    let size_at = out.len();
    out.put_u16(0);
    let start = out.len();
    row.encode(out, code_page);
    let size = u16::try_from(out.len().saturating_sub(start)).unwrap_or(u16::MAX);
    out.patch_u16(size_at, size);
}

#[derive(Debug, Clone, PartialEq)]
pub struct OpenRecipientRow<'x> {
    pub recipient_type: u8,
    pub code_page_id: u16,
    pub row: RecipientRow<'x>,
}

impl OpenRecipientRow<'_> {
    fn encode(&self, out: &mut Vec<u8>) {
        out.put_u8(self.recipient_type);
        out.put_u16(self.code_page_id);
        out.put_u16(0);
        put_sized_recipient(out, &self.row, CodePage(self.code_page_id));
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct OpenMessageResponse<'x> {
    pub has_named_properties: bool,
    pub subject_prefix: TypedString<'x>,
    pub normalized_subject: TypedString<'x>,
    pub recipient_count: u16,
    pub recipient_columns: &'x [PropTag],
    pub recipient_rows: &'x [OpenRecipientRow<'x>],
}

pub type ReloadCachedInformationResponse<'x> = OpenMessageResponse<'x>;

impl RopResponse for OpenMessageResponse<'_> {
    fn encode(&self, out: &mut Vec<u8>) {
        out.put_u8(u8::from(self.has_named_properties));
        self.subject_prefix.encode(out);
        self.normalized_subject.encode(out);
        out.put_u16(self.recipient_count);
        let columns = u16::try_from(self.recipient_columns.len()).unwrap_or(u16::MAX);
        out.put_u16(columns);
        for tag in self.recipient_columns.iter().take(usize::from(columns)) {
            out.put_u32(tag.0);
        }
        let rows = u8::try_from(self.recipient_rows.len()).unwrap_or(u8::MAX);
        out.put_u8(rows);
        for row in self.recipient_rows.iter().take(usize::from(rows)) {
            row.encode(out);
        }
    }

    fn encoded_len_hint(&self) -> usize {
        6_usize
            .saturating_add(self.subject_prefix.len_hint())
            .saturating_add(self.normalized_subject.len_hint())
            .saturating_add(self.recipient_columns.len().saturating_mul(4))
            .saturating_add(self.recipient_rows.len().saturating_mul(RECIPIENT_ROW_HINT))
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct OpenEmbeddedMessageResponse<'x> {
    pub message_id: Eid,
    pub message: OpenMessageResponse<'x>,
}

impl RopResponse for OpenEmbeddedMessageResponse<'_> {
    fn encode(&self, out: &mut Vec<u8>) {
        out.put_u8(0);
        out.extend_from_slice(&self.message_id.to_wire());
        self.message.encode(out);
    }

    fn encoded_len_hint(&self) -> usize {
        9_usize.saturating_add(self.message.encoded_len_hint())
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct ReadRecipientRow<'x> {
    pub row_id: u32,
    pub recipient_type: u8,
    pub code_page_id: u16,
    pub row: RecipientRow<'x>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ReadRecipientsResponse<'x> {
    pub rows: &'x [ReadRecipientRow<'x>],
}

impl RopResponse for ReadRecipientsResponse<'_> {
    fn encode(&self, out: &mut Vec<u8>) {
        let rows = u8::try_from(self.rows.len()).unwrap_or(u8::MAX);
        out.put_u8(rows);
        for row in self.rows.iter().take(usize::from(rows)) {
            out.put_u32(row.row_id);
            out.put_u8(row.recipient_type);
            out.put_u16(row.code_page_id);
            out.put_u16(0);
            put_sized_recipient(out, &row.row, CodePage(row.code_page_id));
        }
    }

    fn encoded_len_hint(&self) -> usize {
        1_usize.saturating_add(self.rows.len().saturating_mul(RECIPIENT_ROW_HINT))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GetAddressTypesResponse<'x> {
    pub address_types: &'x [&'x [u8]],
}

impl RopResponse for GetAddressTypesResponse<'_> {
    fn encode(&self, out: &mut Vec<u8>) {
        let count = u16::try_from(self.address_types.len()).unwrap_or(u16::MAX);
        let types = self
            .address_types
            .get(..usize::from(count))
            .unwrap_or(self.address_types);
        let size = types.iter().fold(0usize, |acc, t| {
            acc.saturating_add(t.len()).saturating_add(1)
        });
        out.put_u16(count);
        out.put_u16(u16::try_from(size).unwrap_or(u16::MAX));
        for address_type in types {
            out.put_ascii_z(address_type);
        }
    }

    fn encoded_len_hint(&self) -> usize {
        self.address_types
            .iter()
            .fold(4, |acc, t| acc.saturating_add(t.len()).saturating_add(1))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OptionsDataResponse;

const OPTIONS_DATA_RESERVED: u8 = 0x01;
const OPTIONS_INFO_SIZE: u16 = 300;
const OPTIONS_INFO: [u8; OPTIONS_INFO_SIZE as usize] = [0; OPTIONS_INFO_SIZE as usize];

impl RopResponse for OptionsDataResponse {
    fn encode(&self, out: &mut Vec<u8>) {
        out.put_u8(OPTIONS_DATA_RESERVED);
        out.put_u16(OPTIONS_INFO_SIZE);
        out.extend_from_slice(&OPTIONS_INFO);
        out.put_u16(0);
    }

    fn encoded_len_hint(&self) -> usize {
        OPTIONS_INFO.len().saturating_add(5)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransferBody<'x> {
    Buffer(&'x [u8]),
    Backoff(u32),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FastTransferSourceGetBufferResponse<'x> {
    pub transfer_status: TransferStatus,
    pub in_progress_count: u16,
    pub total_step_count: u16,
    pub body: TransferBody<'x>,
}

impl RopResponse for FastTransferSourceGetBufferResponse<'_> {
    fn encode(&self, out: &mut Vec<u8>) {
        out.put_u16(self.transfer_status as u16);
        out.put_u16(self.in_progress_count);
        out.put_u16(self.total_step_count);
        out.put_u8(0);
        match self.body {
            TransferBody::Buffer(data) => {
                let data = data.get(..TRANSFER_BUFFER_MAX).unwrap_or(data);
                out.put_u16(u16::try_from(data.len()).unwrap_or(u16::MAX));
                out.extend_from_slice(data);
            }
            TransferBody::Backoff(time) => {
                out.put_u16(0);
                out.put_u32(time);
            }
        }
    }

    fn encoded_len_hint(&self) -> usize {
        9_usize.saturating_add(match self.body {
            TransferBody::Buffer(data) => data.len(),
            TransferBody::Backoff(_) => 4,
        })
    }
}
