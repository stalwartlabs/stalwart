/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{
    execute::MailboxView,
    props::{MAX_INLINE_VALUE, PropBag},
};
use crate::{
    folders::FolderTree,
    identity::{legacy_dn, mailbox_guid, replica_guid},
    mapi::ids::{IdSpace, MapiId, fixed},
};
use common::{MessageStoreCache, Server, auth::AccountInfo, cache::exchange::foreign_replid};
use email::cache::mailbox::MailboxCacheAccess;
use exchange_proto::{
    common::{Guid, LeWriter},
    ids::{
        Gid, ReplGuid, ReplId,
        entryid::{
            AddressBookEntryId, EntryId, FolderEntryId, MessageEntryId, StoreEntryId, object_type,
            provider, wrapped_type,
        },
        essdn::LegacyDn,
    },
    mapi::{
        prop::{PropTag, tags},
        rop::responses::SPECIAL_FOLDER_COUNT,
    },
};
use jmap_proto::request::capability::{Capabilities, Capability};
use std::borrow::Cow;
use types::special_use::SpecialUse;

const MAPI_STORE: i32 = 1;
const DT_MAILUSER: u32 = 0;
const KB: u64 = 1024;
const UNLIMITED_KB: i32 = i32::MAX;

const STORE_ENTRYID_UNIQUE: i32 = 0x0000_0001;
const STORE_SEARCH_OK: i32 = 0x0000_0004;
const STORE_MODIFY_OK: i32 = 0x0000_0008;
const STORE_CREATE_OK: i32 = 0x0000_0010;
const STORE_ATTACH_OK: i32 = 0x0000_0020;
const STORE_OLE_OK: i32 = 0x0000_0040;
const STORE_NOTIFY_OK: i32 = 0x0000_0100;
const STORE_MV_PROPS_OK: i32 = 0x0000_0200;
const STORE_CATEGORIZE_OK: i32 = 0x0000_0400;
const STORE_RTF_OK: i32 = 0x0000_0800;
const STORE_RESTRICTION_OK: i32 = 0x0000_1000;
const STORE_SORT_OK: i32 = 0x0000_2000;
const STORE_HTML_OK: i32 = 0x0001_0000;
const STORE_ANSI_OK: i32 = 0x0002_0000;
const STORE_UNICODE_OK: i32 = 0x0004_0000;
const STORE_SUPPORT_MASK: i32 = STORE_ENTRYID_UNIQUE
    | STORE_SEARCH_OK
    | STORE_MODIFY_OK
    | STORE_CREATE_OK
    | STORE_ATTACH_OK
    | STORE_OLE_OK
    | STORE_NOTIFY_OK
    | STORE_MV_PROPS_OK
    | STORE_CATEGORIZE_OK
    | STORE_RTF_OK
    | STORE_RESTRICTION_OK
    | STORE_SORT_OK
    | STORE_HTML_OK
    | STORE_ANSI_OK
    | STORE_UNICODE_OK;

const MDB_PROVIDER: PropTag = PropTag(0x3414_0102);
const REPLID_GUID_PAIR_LEN: usize = 18;
const MAX_REPLID_GUID_PAIRS: usize = MAX_INLINE_VALUE / REPLID_GUID_PAIR_LEN;

#[derive(Debug, Clone, Copy)]
pub struct SpecialFolders {
    pub inbox: MapiId,
    pub sent: MapiId,
    pub trash: MapiId,
}

impl SpecialFolders {
    pub fn new(messages: Option<&MessageStoreCache>) -> Self {
        let role = |role: SpecialUse| {
            messages
                .and_then(|messages| messages.mailboxes.mailbox_by_role(&role))
                .map_or(fixed::IPM_SUBTREE, |mailbox| {
                    MapiId::new(IdSpace::Mailbox, mailbox.document_id)
                })
        };
        SpecialFolders {
            inbox: role(SpecialUse::Inbox),
            sent: role(SpecialUse::Sent),
            trash: role(SpecialUse::Trash),
        }
    }

    pub fn logon_ids(&self) -> [MapiId; SPECIAL_FOLDER_COUNT] {
        [
            fixed::ROOT,
            fixed::DEFERRED_ACTION,
            fixed::SPOOLER_QUEUE,
            fixed::IPM_SUBTREE,
            self.inbox,
            fixed::OUTBOX,
            self.sent,
            self.trash,
            fixed::COMMON_VIEWS,
            fixed::SCHEDULE,
            fixed::FINDER,
            fixed::VIEWS,
            fixed::SHORTCUTS,
        ]
    }
}

#[derive(Debug, Clone, Copy)]
pub struct StoreGuids {
    pub mailbox: Guid,
    pub replica: ReplGuid,
}

impl StoreGuids {
    pub fn new(store_instance: u64, account_id: u32) -> Self {
        StoreGuids {
            mailbox: mailbox_guid(store_instance, account_id),
            replica: replica_guid(store_instance, account_id),
        }
    }

    pub fn folder_entry_id(&self, id: MapiId) -> EntryId<'static> {
        EntryId::Folder(FolderEntryId {
            flags: 0,
            provider: self.mailbox,
            folder_type: object_type::PRIVATE_FOLDER,
            gid: Gid {
                guid: self.replica,
                counter: id.to_eid().counter,
            },
        })
    }

    pub fn encode_replid_guid_map(&self, foreign: &[[u8; 16]], out: &mut Vec<u8>) {
        let foreign = foreign.get(..MAX_REPLID_GUID_PAIRS - 1).unwrap_or(foreign);
        out.reserve((foreign.len() + 1) * REPLID_GUID_PAIR_LEN);
        out.put_u16(ReplId::LOCAL.0);
        out.put_guid(&self.replica.0);
        for (index, guid) in foreign.iter().enumerate() {
            let Some(replid) = foreign_replid(index) else {
                break;
            };
            out.put_u16(replid);
            out.extend_from_slice(guid);
        }
    }

    pub fn gid(&self, id: MapiId) -> Gid {
        Gid {
            guid: self.replica,
            counter: id.to_eid().counter,
        }
    }

    pub fn message_entry_id(&self, folder: MapiId, message: MapiId) -> EntryId<'static> {
        EntryId::Message(MessageEntryId {
            flags: 0,
            provider: self.mailbox,
            message_type: object_type::PRIVATE_MESSAGE,
            folder: self.gid(folder),
            message: self.gid(message),
        })
    }
}

pub fn visible_folder(tree: &FolderTree, id: MapiId) -> MapiId {
    if id.to_node().is_some_and(|node| tree.get(node).is_some()) {
        id
    } else {
        fixed::IPM_SUBTREE
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StoreView {
    Full,
    Identity,
}

pub async fn store_props(
    server: &Server,
    mailbox: &MailboxView,
    tree: &FolderTree,
    view: StoreView,
) -> trc::Result<PropBag> {
    let account_id = mailbox.id;
    let messages = mailbox.messages.as_deref();
    let info = server.account_info(account_id).await?;
    let guids = StoreGuids::new(mailbox.exchange.store_instance, account_id);
    let folders = SpecialFolders::new(messages);
    let dn = account_dn(account_id, &info);
    let name = info
        .account
        .description
        .as_deref()
        .unwrap_or(info.account.name.as_ref());

    let mut props = PropBag::with_capacity(512);
    props.push_i32(tags::OBJECT_TYPE, MAPI_STORE);
    props.push_text(tags::DISPLAY_NAME, name);
    props.push_text(tags::MAILBOX_OWNER_NAME, name);
    if let Some(dn) = &dn {
        props.push_entry_id(tags::MAILBOX_OWNER_ENTRY_ID, &mail_user_entry_id(dn));
        props.push_entry_id(
            tags::STORE_ENTRY_ID,
            &EntryId::Store(StoreEntryId {
                flags: 0,
                wrapped_provider: provider::WRAPPED_PRIVATE,
                wrapped_type: wrapped_type::MAILBOX,
                server: Cow::Borrowed(server.registry().local_hostname().as_bytes()),
                mailbox_dn: Some(Cow::Borrowed(dn.as_str().as_bytes())),
            }),
        );
    }
    props.push_binary(tags::STORE_RECORD_KEY, guids.mailbox.as_bytes());
    props.push_binary(tags::RECORD_KEY, guids.mailbox.as_bytes());
    props.push_binary(MDB_PROVIDER, provider::WRAPPED_PRIVATE.as_bytes());
    props.push_i32(tags::STORE_SUPPORT_MASK, STORE_SUPPORT_MASK);
    props.push_binary_with(tags::SERIALIZED_REPLID_GUID_MAP, |out| {
        guids.encode_replid_guid_map(&mailbox.exchange.replicas, out)
    });
    for (tag, id) in [
        (tags::IPM_SUBTREE_ENTRY_ID, fixed::IPM_SUBTREE),
        (tags::IPM_OUTBOX_ENTRY_ID, fixed::OUTBOX),
        (tags::IPM_WASTEBASKET_ENTRY_ID, folders.trash),
        (tags::IPM_SENT_MAIL_ENTRY_ID, folders.sent),
        (tags::VIEWS_ENTRY_ID, fixed::VIEWS),
        (tags::COMMON_VIEWS_ENTRY_ID, fixed::COMMON_VIEWS),
        (tags::FINDER_ENTRY_ID, fixed::FINDER),
    ] {
        props.push_entry_id(tag, &guids.folder_entry_id(visible_folder(tree, id)));
    }
    let quota = match info.account.quota_disk {
        0 => UNLIMITED_KB,
        quota => i32::try_from(quota / KB).unwrap_or(i32::MAX),
    };
    props.push_i32(tags::PROHIBIT_SEND_QUOTA, quota);
    props.push_i32(tags::PROHIBIT_RECEIVE_QUOTA, quota);
    if view == StoreView::Identity {
        return Ok(props);
    }
    if let Some(messages) = messages {
        props.push_i32(
            tags::MESSAGE_SIZE,
            i32::try_from(messages.emails.size).unwrap_or(i32::MAX),
        );
        props.push_i64(
            tags::MESSAGE_SIZE_EXTENDED,
            i64::try_from(messages.emails.size).unwrap_or(i64::MAX),
        );
        props.push_i32(
            tags::CONTENT_COUNT,
            i32::try_from(messages.emails.len()).unwrap_or(i32::MAX),
        );
    }
    if let Some(limit) = extended_rule_size_limit(server) {
        props.push_i32(
            tags::EXTENDED_RULE_SIZE_LIMIT,
            i32::try_from(limit).unwrap_or(i32::MAX),
        );
    }
    let submit_kb = u64::try_from(server.core.email.mail_max_size).unwrap_or(u64::MAX) / KB;
    let submit_limit = match submit_kb {
        0 => UNLIMITED_KB,
        limit => i32::try_from(limit).unwrap_or(i32::MAX),
    };
    props.push_i32(tags::MAXIMUM_SUBMIT_MESSAGE_SIZE, submit_limit);
    Ok(props)
}

pub async fn push_user_entry_id(
    server: &Server,
    account_id: u32,
    props: &mut PropBag,
) -> trc::Result<()> {
    let info = server.account_info(account_id).await?;
    if let Some(dn) = account_dn(account_id, &info) {
        props.push_entry_id(tags::USER_ENTRY_ID, &mail_user_entry_id(&dn));
    }
    Ok(())
}

fn account_dn(account_id: u32, info: &AccountInfo) -> Option<LegacyDn> {
    let primary = info
        .addresses
        .first()
        .map_or(info.account.name.as_ref(), String::as_str);
    legacy_dn(account_id, primary)
}

fn mail_user_entry_id(dn: &LegacyDn) -> EntryId<'_> {
    EntryId::AddressBook(AddressBookEntryId {
        flags: 0,
        display_type: DT_MAILUSER,
        dn: Cow::Borrowed(dn.as_str().as_bytes()),
    })
}

pub fn extended_rule_size_limit(server: &Server) -> Option<u64> {
    match server
        .core
        .jmap
        .capabilities
        .account
        .get(&Capability::Sieve)
    {
        Some(Capabilities::SieveAccount(sieve)) => Some(sieve.max_script_size),
        _ => None,
    }
}

pub struct ReceiveFolder {
    pub message_class: &'static [u8],
    pub folder: MapiId,
}

const MAX_MESSAGE_CLASS_LEN: usize = 255;
const RECEIVE_CLASSES: [&[u8]; 4] = [b"", b"IPC", b"IPM", b"REPORT.IPM"];

impl ReceiveFolder {
    pub fn table(inbox: MapiId) -> impl Iterator<Item = ReceiveFolder> {
        RECEIVE_CLASSES
            .into_iter()
            .map(move |message_class| ReceiveFolder {
                message_class,
                folder: Self::folder_for(message_class, inbox),
            })
    }

    pub fn is_valid_class(message_class: &[u8]) -> bool {
        message_class.len() <= MAX_MESSAGE_CLASS_LEN
            && message_class
                .iter()
                .all(|byte| (0x20..=0x7E).contains(byte))
            && message_class.first() != Some(&b'.')
            && message_class.last() != Some(&b'.')
            && !message_class.windows(2).any(|pair| pair == b"..")
    }

    pub fn is_protected_class(message_class: &[u8]) -> bool {
        hashify::set_ignore_case!(message_class, "IPM", "REPORT.IPM")
    }

    pub fn is_mapped_class(message_class: &[u8]) -> bool {
        message_class.is_empty() || message_class.eq_ignore_ascii_case(b"IPC")
    }

    pub fn resolve(message_class: &[u8], inbox: MapiId) -> ReceiveFolder {
        let explicit = RECEIVE_CLASSES
            .into_iter()
            .rev()
            .find(|candidate| class_has_prefix(message_class, candidate))
            .unwrap_or_default();
        ReceiveFolder {
            message_class: explicit,
            folder: Self::folder_for(explicit, inbox),
        }
    }

    fn folder_for(message_class: &[u8], inbox: MapiId) -> MapiId {
        if message_class.eq_ignore_ascii_case(b"IPC") {
            fixed::ROOT
        } else {
            inbox
        }
    }
}

pub(super) fn class_has_prefix(message_class: &[u8], prefix: &[u8]) -> bool {
    if prefix.is_empty() {
        return true;
    }
    message_class
        .split_at_checked(prefix.len())
        .is_some_and(|(head, rest)| {
            head.eq_ignore_ascii_case(prefix) && matches!(rest.first(), None | Some(b'.'))
        })
}

#[cfg(all(test, stalwart_tests))]
#[rustfmt::skip]
#[path = "../../../../../../stalwart-tests/unit/exchange/src/mapi/emsmdb/store/tests.rs"]
mod tests;
