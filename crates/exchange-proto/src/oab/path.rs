/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    common::{Braces, Guid, HexCase},
    xml::writer::push_u64,
};

pub const MANIFEST_NAME: &str = "oab.xml";
pub const ROOT: &str = "oab";
const FULL_INFIX: &str = "-data-";
const TEMPLATE_INFIX: &str = "-lng0409-";
const FILE_SUFFIX: &str = ".lzx";
const GUID_TEXT_LEN: usize = 36;
const MAX_SEQ_DIGITS: usize = 10;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OabFile {
    Manifest,
    Full { seq: u32 },
    Template { seq: u32 },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OabRequest {
    pub guid: Guid,
    pub file: OabFile,
}

impl OabRequest {
    pub fn parse(path: &str) -> Option<Self> {
        let (root, rest) = path.strip_prefix('/')?.split_once('/')?;
        if !root.eq_ignore_ascii_case(ROOT) {
            return None;
        }
        let (guid, file) = rest.split_once('/')?;
        let guid = parse_guid(guid)?;
        let file = if file.eq_ignore_ascii_case(MANIFEST_NAME) {
            OabFile::Manifest
        } else {
            let (file_guid, name) = file.split_at_checked(GUID_TEXT_LEN)?;
            if parse_guid(file_guid)? != guid {
                return None;
            }
            let name = name.strip_suffix(FILE_SUFFIX)?;
            if let Some(seq) = name.strip_prefix(FULL_INFIX) {
                OabFile::Full {
                    seq: parse_seq(seq)?,
                }
            } else {
                OabFile::Template {
                    seq: parse_seq(name.strip_prefix(TEMPLATE_INFIX)?)?,
                }
            }
        };
        Some(OabRequest { guid, file })
    }
}

impl OabFile {
    pub fn write_name(self, guid: Guid, out: &mut Vec<u8>) {
        let (infix, seq) = match self {
            OabFile::Manifest => {
                out.extend_from_slice(MANIFEST_NAME.as_bytes());
                return;
            }
            OabFile::Full { seq } => (FULL_INFIX, seq),
            OabFile::Template { seq } => (TEMPLATE_INFIX, seq),
        };
        guid.write_text(out, HexCase::Lower, Braces::None);
        out.extend_from_slice(infix.as_bytes());
        push_u64(out, u64::from(seq));
        out.extend_from_slice(FILE_SUFFIX.as_bytes());
    }
}

fn parse_guid(text: &str) -> Option<Guid> {
    if text.len() == GUID_TEXT_LEN {
        Guid::parse_text(text.as_bytes())
    } else {
        None
    }
}

fn parse_seq(text: &str) -> Option<u32> {
    if text.is_empty()
        || text.len() > MAX_SEQ_DIGITS
        || !text.bytes().all(|b| b.is_ascii_digit())
        || (text.len() > 1 && text.starts_with('0'))
    {
        return None;
    }
    text.parse().ok()
}
