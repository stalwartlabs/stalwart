/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::TableRow;
use crate::{
    folders::{
        FolderNode,
        rights::{CONTAINER_VISIBLE, MAILBOX_VISIBLE, member_rights},
    },
    mapi::{
        emsmdb::{
            execute::{RopContext, RopError, RopResult},
            props::PropBag,
            state::{FolderObject, ServerObject, TableKind, TableObject},
        },
        nspi::book::acl_member,
    },
    store::{FolderKind, FolderRef},
};
use email::cache::mailbox::MailboxCacheAccess;
use exchange_proto::mapi::{
    ErrorCode,
    prop::{PropTag, tags},
    rop::{
        DecodedRop,
        requests::{GetPermissionsTable, GetRulesTable},
    },
};
use groupware::cache::GroupwareCache;
use smallvec::SmallVec;
use types::{
    acl::{Acl, AclGrant},
    collection::SyncCollection,
};
use utils::map::bitmap::Bitmap;

const TABLE_INCLUDE_FREE_BUSY: u8 = 0x02;
const TABLE_USE_UNICODE: u8 = 0x40;

pub(crate) const MEMBER_DEFAULT: i64 = 0;
pub(crate) const MEMBER_ANONYMOUS: i64 = -1;
const ANONYMOUS_KEY: u64 = 1 << 32;
const ANONYMOUS_NAME: &str = "Anonymous";

pub const PERMISSION_COLUMNS: [PropTag; 4] = [
    tags::MEMBER_ID,
    tags::MEMBER_NAME,
    tags::MEMBER_RIGHTS,
    tags::ENTRY_ID,
];

type Grants = SmallVec<[(u32, Bitmap<Acl>); 4]>;

struct FolderGrants {
    grants: Grants,
    visible: &'static [Acl],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AclReader {
    Owner,
    Shared,
}

impl AclReader {
    fn may_read(self, grants: &[(u32, Bitmap<Acl>)], is_member: impl Fn(u32) -> bool) -> bool {
        match self {
            AclReader::Owner => true,
            AclReader::Shared => grants
                .iter()
                .any(|(account_id, grants)| grants.contains(Acl::Share) && is_member(*account_id)),
        }
    }
}

fn reserved_row(key: u64, member_id: i64, name: &str) -> TableRow {
    let mut bag = PropBag::with_capacity(name.len());
    bag.push_i64(tags::MEMBER_ID, member_id);
    bag.push_text(tags::MEMBER_NAME, name);
    bag.push_i32(tags::MEMBER_RIGHTS, 0);
    bag.push_binary(tags::ENTRY_ID, &[]);
    TableRow { key, bag }
}

fn folder_input(ctx: &RopContext<'_, '_>, rop: &DecodedRop<'_>) -> Result<FolderObject, RopError> {
    match ctx.state.get(ctx.input(rop.header.input_handle)?) {
        Some(ServerObject::Folder(folder)) => Ok(*folder),
        Some(_) => Err(RopError::Code(ErrorCode::NOT_SUPPORTED)),
        None => Err(RopError::Code(ErrorCode::NULL_OBJECT)),
    }
}

impl RopContext<'_, '_> {
    pub fn get_permissions_table(
        &mut self,
        rop: &DecodedRop<'_>,
        request: &GetPermissionsTable,
    ) -> RopResult {
        let folder = folder_input(self, rop)?;
        let kind = TableKind::Permissions {
            free_busy: request.table_flags & TABLE_INCLUDE_FREE_BUSY != 0,
        };
        self.open_rop_table(rop, request.output_handle_index, folder, kind)
    }

    pub fn get_rules_table(&mut self, rop: &DecodedRop<'_>, request: &GetRulesTable) -> RopResult {
        let folder = folder_input(self, rop)?;
        if request.table_flags & !TABLE_USE_UNICODE != 0 {
            return Err(RopError::Code(ErrorCode::NOT_SUPPORTED));
        }
        self.open_rop_table(rop, request.output_handle_index, folder, TableKind::Rules)
    }

    fn open_rop_table(
        &mut self,
        rop: &DecodedRop<'_>,
        index: u8,
        folder: FolderObject,
        kind: TableKind,
    ) -> RopResult {
        let logon_id = self
            .state
            .logon_id(self.input(rop.header.input_handle)?)
            .ok_or(RopError::Code(ErrorCode::NULL_OBJECT))?;
        self.open_table(index, logon_id, TableObject::new(folder, kind, true))?;
        self.respond_empty(rop, index)
    }

    pub(super) async fn permission_rows(
        &mut self,
        table: &TableObject,
        free_busy: bool,
    ) -> Result<Vec<TableRow>, RopError> {
        let mailbox_id = table.folder.mailbox_id;
        let node = table
            .folder
            .id()
            .and_then(|id| id.to_node())
            .ok_or(ErrorCode::OBJECT_DELETED)?;
        let FolderGrants { grants, visible } = self.folder_grants(mailbox_id, node).await?;
        let request = self.request;
        let access_token = request.access_token;
        let access = if access_token.is_member(mailbox_id) {
            AclReader::Owner
        } else {
            AclReader::Shared
        };
        if !access.may_read(&grants, |account_id| access_token.is_member(account_id)) {
            return Err(RopError::Code(ErrorCode::ACCESS_DENIED));
        }
        let mut rows = Vec::with_capacity(grants.len() + 2);
        rows.push(reserved_row(0, MEMBER_DEFAULT, ""));
        rows.push(reserved_row(
            ANONYMOUS_KEY,
            MEMBER_ANONYMOUS,
            ANONYMOUS_NAME,
        ));
        for (account_id, grants) in grants {
            let Some(member) = acl_member(request.server, account_id).await? else {
                continue;
            };
            let member_id = u64::from(account_id) + 1;
            let display_name = member.display_name();
            let mut bag = PropBag::with_capacity(display_name.len() + member.permanent_id.len());
            bag.push_i64(tags::MEMBER_ID, member_id.cast_signed());
            bag.push_text(tags::MEMBER_NAME, display_name);
            bag.push_i32(
                tags::MEMBER_RIGHTS,
                member_rights(grants, visible, free_busy),
            );
            bag.push_binary(tags::ENTRY_ID, &member.permanent_id);
            rows.push(TableRow {
                key: member_id,
                bag,
            });
        }
        Ok(rows)
    }

    async fn folder_grants(
        &mut self,
        mailbox_id: u32,
        node: FolderNode,
    ) -> trc::Result<FolderGrants> {
        let collect = |acls: &[AclGrant], visible| FolderGrants {
            grants: acls
                .iter()
                .map(|grant| (grant.account_id, grant.grants))
                .collect(),
            visible,
        };
        let none = FolderGrants {
            grants: Grants::new(),
            visible: MAILBOX_VISIBLE,
        };
        let FolderNode::Stored(FolderRef { kind, id }) = node else {
            return Ok(none);
        };
        let collection = match kind {
            FolderKind::Mailbox => {
                return Ok(self
                    .mailbox(mailbox_id)
                    .await?
                    .messages
                    .as_ref()
                    .and_then(|messages| messages.mailbox_by_id(&id))
                    .map_or(none, |mailbox| collect(&mailbox.acls, MAILBOX_VISIBLE)));
            }
            FolderKind::Calendar => SyncCollection::Calendar,
            FolderKind::AddressBook => SyncCollection::AddressBook,
            FolderKind::Virtual | FolderKind::FileNode => return Ok(none),
        };
        let resources = self
            .request
            .server
            .fetch_groupware_resources(mailbox_id, mailbox_id, collection)
            .await?;
        Ok(resources
            .container_resource_by_id(id)
            .map_or(none, |resource| collect(resource.acls(), CONTAINER_VISIBLE)))
    }
}

#[cfg(all(test, stalwart_tests))]
#[rustfmt::skip]
#[path = "../../../../../../../stalwart-tests/unit/exchange/src/mapi/emsmdb/table/permissions/tests.rs"]
mod tests;
