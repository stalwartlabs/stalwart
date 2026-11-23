/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */
use crate::protocol::push_int;
use compact_str::CompactString;
use types::acl::Acl;
use utils::map::bitmap::Bitmap;

use super::{Flag, ImapResponse, ObjectId, Sequence, list::ListItem, store::Operation};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Arguments {
    pub tag: CompactString,
    pub mailbox_name: CompactString,
    pub condstore: bool,
    pub qresync: Option<QResync>,
    pub objectid: Option<ObjectId>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QResync {
    pub uid_validity: u32,
    pub modseq: u64,
    pub known_uids: Option<Sequence>,
    pub seq_match: Option<(Sequence, Sequence)>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HighestModSeq(u64);

#[derive(Debug, Clone)]
pub struct Response {
    pub mailbox: ListItem,
    pub total_messages: usize,
    pub recent_messages: usize,
    pub unseen_seq: u32,
    pub uid_validity: u32,
    pub uid_next: u32,
    pub is_rev2: bool,
    pub is_utf8: bool,
    pub highest_modseq: Option<HighestModSeq>,
    pub objectid: Option<ObjectId>,
    pub permanent_flags: PermanentFlags,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PermanentFlags {
    All,
    AllButDeleted,
    DeletedOnly,
    None,
}

#[derive(Debug, Clone)]
pub struct Exists {
    pub total_messages: usize,
}

impl ImapResponse for Response {
    fn serialize_into(&self, buf: &mut Vec<u8>) {
        buf.extend_from_slice(b"* ");
        push_int(buf, self.total_messages);
        if !self.is_rev2 && self.recent_messages > 0 {
            buf.extend_from_slice(
                b" EXISTS\r\n* FLAGS (\\Answered \\Flagged \\Deleted \\Seen \\Draft \\Recent)\r\n",
            );
        } else {
            buf.extend_from_slice(
                b" EXISTS\r\n* FLAGS (\\Answered \\Flagged \\Deleted \\Seen \\Draft)\r\n",
            );
        }
        if self.is_rev2 {
            self.mailbox
                .serialize(buf, self.is_rev2, self.is_utf8, false);
        } else {
            buf.extend_from_slice(b"* ");
            push_int(buf, self.recent_messages);
            buf.extend_from_slice(b" RECENT\r\n");
            if self.unseen_seq > 0 {
                buf.extend_from_slice(b"* OK [UNSEEN ");
                push_int(buf, self.unseen_seq);
                buf.extend_from_slice(b"] Unseen messages\r\n");
            }
        }
        self.permanent_flags.serialize(buf);
        buf.extend_from_slice(b"* OK [UIDVALIDITY ");
        push_int(buf, self.uid_validity);
        buf.extend_from_slice(b"] UIDs valid\r\n* OK [UIDNEXT ");
        push_int(buf, self.uid_next);
        buf.extend_from_slice(b"] Next predicted UID\r\n");
        if let Some(highest_modseq) = &self.highest_modseq {
            highest_modseq.serialize(buf);
        }
        if let Some(objectid) = &self.objectid {
            buf.extend_from_slice(b"* OK [");
            objectid.serialize(buf);
            buf.extend_from_slice(b"] Object identifiers\r\n");
        }
    }

    fn size_hint(&self) -> usize {
        const FRAMING_LEN: usize = 320;
        const OBJECT_ID_LEN: usize = 96;
        const MODSEQ_LEN: usize = 64;

        FRAMING_LEN
            + self.mailbox.mailbox_name.len() * 2
            + self.mailbox.attributes.len() * 16
            + if self.highest_modseq.is_some() {
                MODSEQ_LEN
            } else {
                0
            }
            + if self.objectid.is_some() {
                OBJECT_ID_LEN
            } else {
                0
            }
    }
}

impl From<Bitmap<Acl>> for PermanentFlags {
    fn from(acl: Bitmap<Acl>) -> Self {
        match (
            acl.contains(Acl::ModifyItems),
            acl.contains(Acl::RemoveItems),
        ) {
            (true, true) => PermanentFlags::All,
            (true, false) => PermanentFlags::AllButDeleted,
            (false, true) => PermanentFlags::DeletedOnly,
            (false, false) => PermanentFlags::None,
        }
    }
}

impl PermanentFlags {
    pub fn permits(self, flag: &Flag) -> bool {
        match self {
            PermanentFlags::All => true,
            PermanentFlags::AllButDeleted => *flag != Flag::Deleted,
            PermanentFlags::DeletedOnly => *flag == Flag::Deleted,
            PermanentFlags::None => false,
        }
    }

    pub fn permits_any(self, operation: &Operation, flags: &[Flag]) -> bool {
        match self {
            PermanentFlags::None => false,
            _ if *operation == Operation::Set || flags.is_empty() => true,
            _ => flags.iter().any(|flag| self.permits(flag)),
        }
    }

    fn serialize(self, buf: &mut Vec<u8>) {
        buf.extend_from_slice(match self {
            PermanentFlags::All => {
                b"* OK [PERMANENTFLAGS (\\Deleted \\Seen \\Answered \\Flagged \\Draft \\*)] All allowed\r\n".as_slice()
            }
            PermanentFlags::AllButDeleted => {
                b"* OK [PERMANENTFLAGS (\\Seen \\Answered \\Flagged \\Draft \\*)] Limited\r\n"
            }
            PermanentFlags::DeletedOnly => b"* OK [PERMANENTFLAGS (\\Deleted)] Limited\r\n",
            PermanentFlags::None => b"* OK [PERMANENTFLAGS ()] No permanent flags permitted\r\n",
        });
    }
}

impl HighestModSeq {
    pub fn new(modseq: u64) -> Self {
        Self(modseq)
    }

    pub fn serialize(&self, buf: &mut Vec<u8>) {
        buf.extend_from_slice(b"* OK [HIGHESTMODSEQ ");
        push_int(buf, self.0);
        buf.extend_from_slice(b"] Highest Modseq\r\n");
    }

    pub fn into_bytes(self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(64);
        self.serialize(&mut buf);
        buf
    }
}

impl Exists {
    pub fn serialize(&self, buf: &mut Vec<u8>) {
        buf.extend_from_slice(b"* ");
        push_int(buf, self.total_messages);
        buf.extend_from_slice(b" EXISTS\r\n");
    }

    pub fn into_bytes(self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(32);
        self.serialize(&mut buf);
        buf
    }
}

#[cfg(all(test, stalwart_tests))]
#[rustfmt::skip]
#[path = "../../../../../stalwart-tests/unit/imap-proto/src/protocol/select/tests.rs"]
mod tests;
