/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{
    execute::{RopContext, RopError, RopResult},
    table::permissions::{MEMBER_ANONYMOUS, MEMBER_DEFAULT},
};
use crate::{
    folders::{
        AclWriteError, FolderWriteError, FolderWrites,
        rights::{AclTarget, FolderRights, MemberChange, RowMode},
    },
    identity::principal_from_dn,
};
use exchange_proto::{
    ids::entryid::EntryId,
    mapi::{
        ErrorCode,
        prop::{PropValue, tags},
        rop::{DecodedRop, requests::ModifyPermissions},
    },
};
use types::acl::AclGrant;

const REPLACE_ROWS: u8 = 0x01;
const INCLUDE_FREE_BUSY: u8 = 0x02;
const ADD_ROW: u8 = 0x01;
const MODIFY_ROW: u8 = 0x02;
const REMOVE_ROW: u8 = 0x04;
const MAX_ATTEMPTS: usize = 3;
const MEMBER_RIGHTS: i32 = FolderRights::OWNER.bits()
    | FolderRights::FREE_BUSY_SIMPLE.bits()
    | FolderRights::FREE_BUSY_DETAILED.bits();

impl From<AclWriteError> for RopError {
    fn from(err: AclWriteError) -> Self {
        RopError::Code(match err {
            AclWriteError::Folder(err) => err.into(),
            AclWriteError::TooManyShares => ErrorCode::INVALID_PARAM,
            AclWriteError::InvalidGrantee(_) => ErrorCode::NOT_FOUND,
        })
    }
}

fn member_account(member_id: i64) -> Option<u32> {
    match member_id {
        MEMBER_DEFAULT | MEMBER_ANONYMOUS => None,
        member_id => u32::try_from(member_id.checked_sub(1)?).ok(),
    }
}

fn entry_account(entry_id: &[u8]) -> Result<Option<u32>, RopError> {
    if entry_id.is_empty() {
        return Ok(None);
    }
    match EntryId::decode(entry_id) {
        Ok(EntryId::AddressBook(id)) => principal_from_dn(&id.dn)
            .map(Some)
            .ok_or(RopError::Code(ErrorCode::NOT_FOUND)),
        _ => Err(RopError::Code(ErrorCode::NOT_FOUND)),
    }
}

fn member_changes(
    request: &ModifyPermissions<'_>,
    owner_id: u32,
) -> Result<Vec<MemberChange>, RopError> {
    let mode = row_mode(request.modify_flags);
    let mut changes = Vec::with_capacity(request.permissions_data.len());
    for row in request.permissions_data.iter() {
        let mut member_id = None;
        let mut rights = None;
        let mut entry_id = None;
        for (tag, value) in row.values.iter() {
            match (tag, value) {
                (tags::MEMBER_ID, PropValue::I64(value)) => member_id = Some(value),
                (tags::MEMBER_RIGHTS, PropValue::I32(value)) => rights = Some(value),
                (tags::ENTRY_ID, PropValue::Binary(value)) => entry_id = Some(value),
                _ => {}
            }
        }
        let change = match (row.flags, mode) {
            (ADD_ROW, _) => {
                let rights = rights
                    .and_then(known_rights)
                    .ok_or(ErrorCode::INVALID_PARAM)?;
                entry_account(entry_id.unwrap_or_default())?
                    .map(|account_id| MemberChange::Add { account_id, rights })
            }
            (MODIFY_ROW, RowMode::Merge) => {
                let rights = rights
                    .and_then(known_rights)
                    .ok_or(ErrorCode::INVALID_PARAM)?;
                member_id
                    .ok_or(RopError::Code(ErrorCode::INVALID_PARAM))
                    .map(member_account)?
                    .map(|account_id| MemberChange::Modify { account_id, rights })
            }
            (REMOVE_ROW, RowMode::Merge) => member_id
                .ok_or(RopError::Code(ErrorCode::INVALID_PARAM))
                .map(member_account)?
                .map(|account_id| MemberChange::Remove { account_id }),
            _ => return Err(RopError::Code(ErrorCode::INVALID_PARAM)),
        };
        if let Some(change) = change.filter(|change| change.account_id() != owner_id) {
            changes.push(change);
        }
    }
    Ok(changes)
}

fn known_rights(rights: i32) -> Option<i32> {
    (rights & !MEMBER_RIGHTS == 0).then_some(rights)
}

fn row_mode(modify_flags: u8) -> RowMode {
    if modify_flags & REPLACE_ROWS != 0 {
        RowMode::Replace
    } else {
        RowMode::Merge
    }
}

impl MemberChange {
    fn account_id(&self) -> u32 {
        match *self {
            MemberChange::Add { account_id, .. }
            | MemberChange::Modify { account_id, .. }
            | MemberChange::Remove { account_id } => account_id,
        }
    }
}

impl RopContext<'_, '_> {
    pub async fn modify_permissions(
        &mut self,
        rop: &DecodedRop<'_>,
        index: u8,
        request: &ModifyPermissions<'_>,
    ) -> RopResult {
        let folder = self.open_folder_at(self.input(rop.header.input_handle)?)?;
        let Some(target) = AclTarget::of(folder.node) else {
            return self.respond_empty(rop, index);
        };
        let changes = member_changes(request, folder.mailbox_id)?;
        let mode = row_mode(request.modify_flags);
        let free_busy = request.modify_flags & INCLUDE_FREE_BUSY != 0;
        let edit = |current: &[AclGrant]| target.edit(current, &changes, mode, free_busy);
        let request_ctx = self.request;
        let mut attempts = 0;
        let result = loop {
            attempts += 1;
            match request_ctx
                .server
                .folder_set_acl(
                    request_ctx.access_token,
                    folder.mailbox_id,
                    folder.node,
                    &edit,
                )
                .await?
            {
                Err(AclWriteError::Folder(FolderWriteError::Conflict))
                    if attempts < MAX_ATTEMPTS => {}
                result => break result,
            }
        };
        self.invalidate_mailbox();
        result?;
        self.respond_empty(rop, index)
    }
}

#[cfg(all(test, stalwart_tests))]
#[rustfmt::skip]
#[path = "../../../../../../stalwart-tests/unit/exchange/src/mapi/emsmdb/folder_permissions/tests.rs"]
mod tests;
