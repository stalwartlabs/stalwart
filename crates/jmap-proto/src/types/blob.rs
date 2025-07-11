/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::borrow::Borrow;

use store::BlobClass;
use utils::{
    BlobHash,
    codec::{
        base32_custom::{Base32Reader, Base32Writer},
        leb128::{Leb128Iterator, Leb128Writer},
    },
};

use crate::parser::{JsonObjectParser, base32::JsonBase32Reader, json::Parser};

const B_LINKED: u8 = 0x10;
const B_RESERVED: u8 = 0x20;

#[derive(Clone, Debug, PartialEq, Eq, Hash, Default)]
pub struct BlobId {
    pub hash: BlobHash,
    pub class: BlobClass,
    pub section: Option<BlobSection>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct BlobSection {
    pub offset_start: usize,
    pub size: usize,
    pub encoding: u8,
}

impl JsonObjectParser for BlobId {
    fn parse(parser: &mut Parser<'_>) -> trc::Result<Self>
    where
        Self: Sized,
    {
        let mut it = JsonBase32Reader::new(parser);
        BlobId::from_iter(&mut it).ok_or_else(|| it.error())
    }
}

impl BlobId {
    pub fn new(hash: BlobHash, class: BlobClass) -> Self {
        BlobId {
            hash,
            class,
            section: None,
        }
    }

    pub fn new_section(
        hash: BlobHash,
        class: BlobClass,
        offset_start: usize,
        offset_end: usize,
        encoding: impl Into<u8>,
    ) -> Self {
        BlobId {
            hash,
            class,
            section: BlobSection {
                offset_start,
                size: offset_end - offset_start,
                encoding: encoding.into(),
            }
            .into(),
        }
    }

    pub fn with_section_size(mut self, size: usize) -> Self {
        self.section.get_or_insert_with(Default::default).size = size;
        self
    }

    pub fn from_base32(value: impl AsRef<[u8]>) -> Option<Self> {
        BlobId::from_iter(&mut Base32Reader::new(value.as_ref()))
    }

    #[allow(clippy::should_implement_trait)]
    pub fn from_iter<T, U>(it: &mut T) -> Option<Self>
    where
        T: Iterator<Item = U> + Leb128Iterator<U>,
        U: Borrow<u8>,
    {
        let class = *it.next()?.borrow();
        let encoding = class & 0x0F;

        let mut hash = BlobHash::default();
        for byte in hash.as_mut().iter_mut() {
            *byte = *it.next()?.borrow();
        }

        let account_id: u32 = it.next_leb128()?;

        BlobId {
            hash,
            class: if (class & B_LINKED) != 0 {
                BlobClass::Linked {
                    account_id,
                    collection: *it.next()?.borrow(),
                    document_id: it.next_leb128()?,
                }
            } else {
                BlobClass::Reserved {
                    account_id,
                    expires: it.next_leb128()?,
                }
            },
            section: if encoding != 0 {
                BlobSection {
                    offset_start: it.next_leb128()?,
                    size: it.next_leb128()?,
                    encoding: encoding - 1,
                }
                .into()
            } else {
                None
            },
        }
        .into()
    }

    fn serialize_as(&self, writer: &mut impl Leb128Writer) {
        let marker = self
            .section
            .as_ref()
            .map_or(0, |section| section.encoding + 1)
            | if matches!(
                self,
                BlobId {
                    class: BlobClass::Linked { .. },
                    ..
                }
            ) {
                B_LINKED
            } else {
                B_RESERVED
            };

        let _ = writer.write(&[marker]);
        let _ = writer.write(self.hash.as_ref());

        match &self.class {
            BlobClass::Reserved {
                account_id,
                expires,
            } => {
                let _ = writer.write_leb128(*account_id);
                let _ = writer.write_leb128(*expires);
            }
            BlobClass::Linked {
                account_id,
                collection,
                document_id,
            } => {
                let _ = writer.write_leb128(*account_id);
                let _ = writer.write(&[*collection]);
                let _ = writer.write_leb128(*document_id);
            }
        }

        if let Some(section) = &self.section {
            let _ = writer.write_leb128(section.offset_start);
            let _ = writer.write_leb128(section.size);
        }
    }

    pub fn start_offset(&self) -> usize {
        if let Some(section) = &self.section {
            section.offset_start
        } else {
            0
        }
    }
}

impl serde::Serialize for BlobId {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(self.to_string().as_str())
    }
}

impl std::fmt::Display for BlobId {
    #[allow(clippy::unused_io_amount)]
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut writer = Base32Writer::with_capacity(std::mem::size_of::<BlobId>() * 2);
        self.serialize_as(&mut writer);
        f.write_str(&writer.finalize())
    }
}
