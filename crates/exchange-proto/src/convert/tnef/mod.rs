/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

#![deny(
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::cast_possible_truncation
)]

mod message;
mod props;

pub use message::tnef_to_message;
pub(crate) use message::{tnef_message_props, tnef_to_message_at};
pub use props::{TnefProp, TnefProps, TnefRecipients, TnefValue};

use crate::convert::{BlobLimits, ConvertError};

pub const SIGNATURE: u32 = 0x223E_9F78;
pub const TNEF_VERSION: [u8; 4] = [0x00, 0x00, 0x01, 0x00];

pub mod attr {
    pub const OWNER: u32 = 0x0006_0000;
    pub const SENT_FOR: u32 = 0x0006_0001;
    pub const DELEGATE: u32 = 0x0006_0002;
    pub const DATE_START: u32 = 0x0003_0006;
    pub const DATE_END: u32 = 0x0003_0007;
    pub const AID_OWNER: u32 = 0x0005_0008;
    pub const REQUEST_RES: u32 = 0x0004_0009;
    pub const ORIGINAL_MESSAGE_CLASS: u32 = 0x0007_0600;
    pub const FROM: u32 = 0x0000_8000;
    pub const SUBJECT: u32 = 0x0001_8004;
    pub const DATE_SENT: u32 = 0x0003_8005;
    pub const DATE_RECD: u32 = 0x0003_8006;
    pub const MESSAGE_STATUS: u32 = 0x0006_8007;
    pub const MESSAGE_CLASS: u32 = 0x0007_8008;
    pub const MESSAGE_ID: u32 = 0x0001_8009;
    pub const BODY: u32 = 0x0002_800C;
    pub const PRIORITY: u32 = 0x0004_800D;
    pub const ATTACH_DATA: u32 = 0x0006_800F;
    pub const ATTACH_TITLE: u32 = 0x0001_8010;
    pub const ATTACH_META_FILE: u32 = 0x0006_8011;
    pub const ATTACH_CREATE_DATE: u32 = 0x0003_8012;
    pub const ATTACH_MODIFY_DATE: u32 = 0x0003_8013;
    pub const DATE_MODIFIED: u32 = 0x0003_8020;
    pub const ATTACH_TRANSPORT_FILENAME: u32 = 0x0006_9001;
    pub const ATTACH_REND_DATA: u32 = 0x0006_9002;
    pub const MSG_PROPS: u32 = 0x0006_9003;
    pub const RECIP_TABLE: u32 = 0x0006_9004;
    pub const ATTACHMENT: u32 = 0x0006_9005;
    pub const TNEF_VERSION: u32 = 0x0008_9006;
    pub const OEM_CODEPAGE: u32 = 0x0006_9007;
}

const LEVEL_MESSAGE: u8 = 0x01;
const LEVEL_ATTACHMENT: u8 = 0x02;
const ATTR_HEADER_LEN: usize = 9;
const CHECKSUM_LEN: usize = 2;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TnefItem<'a> {
    MessageAttr { id: u32, data: &'a [u8] },
    AttachmentStart,
    AttachAttr { id: u32, data: &'a [u8] },
    Props(TnefProps<'a>),
}

#[derive(Debug, Clone)]
pub struct TnefReader<'a> {
    input: &'a [u8],
    rest: &'a [u8],
    limits: BlobLimits,
    code_page: u32,
    in_attachment: bool,
    pending: Option<(u32, &'a [u8])>,
    failed: bool,
}

struct RawAttr<'a> {
    level: u8,
    id: u32,
    data: &'a [u8],
    offset: u32,
}

impl<'a> TnefReader<'a> {
    pub fn new(b: &'a [u8], limits: &BlobLimits) -> Result<Self, ConvertError> {
        let (signature, rest) = b
            .split_first_chunk::<4>()
            .ok_or(ConvertError::Tnef { offset: 0 })?;
        let (_legacy_key, rest) = rest
            .split_first_chunk::<2>()
            .ok_or(ConvertError::Tnef { offset: 4 })?;
        if u32::from_le_bytes(*signature) != SIGNATURE {
            return Err(ConvertError::Tnef { offset: 0 });
        }
        let mut reader = TnefReader {
            input: b,
            rest,
            limits: *limits,
            code_page: 0,
            in_attachment: false,
            pending: None,
            failed: false,
        };
        let version = reader.raw()?.ok_or(ConvertError::Tnef { offset: 6 })?;
        if version.level != LEVEL_MESSAGE
            || version.id != attr::TNEF_VERSION
            || version.data != TNEF_VERSION
        {
            return Err(ConvertError::Tnef {
                offset: version.offset,
            });
        }
        let code_page = reader.raw()?.ok_or(ConvertError::Tnef {
            offset: reader.offset(),
        })?;
        match code_page.data.first_chunk::<4>() {
            Some(primary)
                if code_page.level == LEVEL_MESSAGE && code_page.id == attr::OEM_CODEPAGE =>
            {
                reader.code_page = u32::from_le_bytes(*primary);
            }
            _ => {
                return Err(ConvertError::Tnef {
                    offset: code_page.offset,
                });
            }
        }
        Ok(reader)
    }

    pub fn code_page(&self) -> u32 {
        self.code_page
    }

    pub fn limits(&self) -> &BlobLimits {
        &self.limits
    }

    fn offset(&self) -> u32 {
        u32::try_from(self.input.len().saturating_sub(self.rest.len())).unwrap_or(u32::MAX)
    }

    fn raw(&mut self) -> Result<Option<RawAttr<'a>>, ConvertError> {
        if self.rest.is_empty() {
            return Ok(None);
        }
        let offset = self.offset();
        let error = ConvertError::Tnef { offset };
        let (header, rest) = self
            .rest
            .split_first_chunk::<ATTR_HEADER_LEN>()
            .ok_or(error)?;
        let [level, id @ .., l0, l1, l2, l3] = *header;
        let id = u32::from_le_bytes(id);
        let len = u32::from_le_bytes([l0, l1, l2, l3]);
        if len > self.limits.max_attr_len {
            return Err(ConvertError::TooLarge);
        }
        let (data, rest) = rest
            .split_at_checked(usize::try_from(len).map_err(|_| error)?)
            .ok_or(error)?;
        let (checksum, rest) = rest.split_first_chunk::<CHECKSUM_LEN>().ok_or(error)?;
        let sum = data
            .iter()
            .fold(0u16, |sum, byte| sum.wrapping_add(u16::from(*byte)));
        let class_attr = matches!(id, attr::MESSAGE_CLASS | attr::ORIGINAL_MESSAGE_CLASS);
        if sum != u16::from_le_bytes(*checksum) && !class_attr {
            return Err(error);
        }
        self.rest = rest;
        let data_offset = offset.saturating_add(9);
        Ok(Some(RawAttr {
            level,
            id,
            data,
            offset: data_offset,
        }))
    }

    #[allow(clippy::should_implement_trait)]
    pub fn next(&mut self) -> Result<Option<TnefItem<'a>>, ConvertError> {
        if self.failed {
            return Ok(None);
        }
        let item = self.next_inner();
        if item.is_err() {
            self.failed = true;
        }
        item
    }

    fn next_inner(&mut self) -> Result<Option<TnefItem<'a>>, ConvertError> {
        if let Some((id, data)) = self.pending.take() {
            return Ok(Some(TnefItem::AttachAttr { id, data }));
        }
        let Some(raw) = self.raw()? else {
            return Ok(None);
        };
        let error = ConvertError::Tnef { offset: raw.offset };
        match (raw.level, raw.id) {
            (LEVEL_MESSAGE, attr::MSG_PROPS) => Ok(Some(TnefItem::Props(TnefProps::new(
                raw.data, raw.offset, raw.id,
            )?))),
            (LEVEL_MESSAGE, _) => Ok(Some(TnefItem::MessageAttr {
                id: raw.id,
                data: raw.data,
            })),
            (LEVEL_ATTACHMENT, attr::ATTACH_REND_DATA) => {
                self.in_attachment = true;
                self.pending = Some((raw.id, raw.data));
                Ok(Some(TnefItem::AttachmentStart))
            }
            (LEVEL_ATTACHMENT, attr::ATTACHMENT) if self.in_attachment => Ok(Some(
                TnefItem::Props(TnefProps::new(raw.data, raw.offset, raw.id)?),
            )),
            (LEVEL_ATTACHMENT, _) if self.in_attachment => Ok(Some(TnefItem::AttachAttr {
                id: raw.id,
                data: raw.data,
            })),
            _ => Err(error),
        }
    }
}

#[cfg(all(test, stalwart_tests))]
#[rustfmt::skip]
#[path = "../../../../../../stalwart-tests/unit/exchange-proto/src/convert/tnef/tests.rs"]
mod tests;
