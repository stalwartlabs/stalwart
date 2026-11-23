/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::context::{EwsAccount, EwsContext, ResolvedMailbox, TreeMemo};
use crate::folders::{
    ExchangeFolders, FolderTree,
    access::{DelegateRights, LogonAccess, ViewRights},
};
use common::Server;
use email::cache::MessageCacheFetch;
use exchange_proto::ews::{EwsRequest, requests::RequestTarget};
use groupware::cache::GroupwareCache;
use std::sync::Arc;
use types::{collection::SyncCollection, type_state::DataType};

fn retargets(request: &EwsRequest<'_>) -> bool {
    matches!(
        request,
        EwsRequest::GetFolder(_)
            | EwsRequest::FindFolder(_)
            | EwsRequest::FindItem(_)
            | EwsRequest::GetItem(_)
            | EwsRequest::GetAttachment(_)
            | EwsRequest::SyncFolderItems(_)
            | EwsRequest::SyncFolderHierarchy(_)
            | EwsRequest::FindConversation(_)
            | EwsRequest::GetConversationItems(_)
            | EwsRequest::FindPeople(_)
            | EwsRequest::CreateItem(_)
            | EwsRequest::UpdateItem(_)
            | EwsRequest::DeleteItem(_)
            | EwsRequest::MoveItem(_)
            | EwsRequest::CopyItem(_)
            | EwsRequest::MarkAllItemsAsRead(_)
            | EwsRequest::CreateAttachment(_)
            | EwsRequest::DeleteAttachment(_)
            | EwsRequest::SendItem(_)
            | EwsRequest::MarkAsJunk(_)
            | EwsRequest::CreateFolder(_)
            | EwsRequest::UpdateFolder(_)
            | EwsRequest::DeleteFolder(_)
            | EwsRequest::MoveFolder(_)
            | EwsRequest::EmptyFolder(_)
            | EwsRequest::ExportItems(_)
            | EwsRequest::UploadItems(_)
    )
}

pub(crate) async fn retarget(
    server: &Server,
    ctx: &mut EwsContext,
    request: &EwsRequest<'_>,
) -> trc::Result<()> {
    if !retargets(request) {
        return Ok(());
    }
    let account_id = match request.target() {
        None | Some(RequestTarget::Caller) => return Ok(()),
        Some(RequestTarget::Account(account_id)) => account_id,
        Some(RequestTarget::Mailbox(address)) => {
            let account_id = server.account_id_from_email(address, false).await?;
            ctx.mailbox = Some(ResolvedMailbox {
                address: address.into(),
                account_id,
            });
            match account_id {
                Some(account_id) => account_id,
                None => return Ok(()),
            }
        }
    };
    if let Some((access, visible)) = view_of(server, ctx, account_id).await? {
        ctx.account.account_id = account_id;
        ctx.access = access;
        ctx.visible = visible;
        ctx.folders_changed();
    }
    Ok(())
}

pub(crate) async fn admitted(
    server: &Server,
    ctx: &EwsContext,
    account_id: u32,
) -> trc::Result<Option<EwsContext>> {
    Ok(view_of(server, ctx, account_id)
        .await?
        .map(|(access, visible)| EwsContext {
            version: ctx.version,
            precision: ctx.precision,
            account: EwsAccount {
                account_id,
                data_types: ctx.account.data_types,
            },
            caller: ctx.caller.clone(),
            access,
            visible,
            mailbox: None,
            owner_tree: TreeMemo::default(),
        }))
}

async fn view_of(
    server: &Server,
    ctx: &EwsContext,
    account_id: u32,
) -> trc::Result<Option<(ViewRights, Option<Arc<FolderTree>>)>> {
    Ok(Some(match LogonAccess::of(&ctx.caller, account_id) {
        None => return Ok(None),
        Some(LogonAccess::Owner) => (ViewRights::Owner, None),
        Some(LogonAccess::Member) => (ViewRights::Member, None),
        Some(LogonAccess::Delegate) => {
            let rights = delegate_rights(server, ctx, account_id).await?;
            let visible = Arc::new(rights.visible_tree());
            (ViewRights::Delegate(Arc::new(rights)), Some(visible))
        }
    }))
}

async fn delegate_rights(
    server: &Server,
    ctx: &EwsContext,
    account_id: u32,
) -> trc::Result<DelegateRights> {
    let types = ctx.account.data_types;
    let tree = Arc::new(server.exchange_folder_tree(account_id, types).await?);
    let mailboxes = if types.contains(DataType::Email) {
        Some(server.get_cached_messages(account_id).await?)
    } else {
        None
    };
    let calendars = if types.contains(DataType::CalendarEvent) {
        Some(
            server
                .fetch_groupware_resources(account_id, account_id, SyncCollection::Calendar)
                .await?,
        )
    } else {
        None
    };
    let address_books = if types.contains(DataType::ContactCard) {
        Some(
            server
                .fetch_groupware_resources(account_id, account_id, SyncCollection::AddressBook)
                .await?,
        )
    } else {
        None
    };
    Ok(DelegateRights::build(
        tree,
        &ctx.caller,
        mailboxes.as_deref(),
        calendars.as_deref(),
        address_books.as_deref(),
    ))
}
