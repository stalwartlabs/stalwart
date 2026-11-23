/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{
    FolderSelector, FolderVariant, resolve_folder,
    write::{FolderOp, folder_info_response, write_status, written_folder},
};
use crate::{
    ews::{
        context::{EwsCaller, EwsContext},
        item::{ItemError, mail_allowed},
    },
    folders::{
        FolderEntry, FolderNode, FolderTree, FolderWriteError,
        copy::{CopyDepth, CopyScope, FolderCopy, FolderCopyError, copy_source},
    },
};
use common::Server;
use exchange_proto::ews::{
    Operation, Status, requests::folder::MoveCopyFolder, types::folder::Folder,
};
use http_proto::HttpResponse;

pub(crate) async fn copy_folder(
    server: &Server,
    ctx: &EwsContext,
    caller: EwsCaller<'_>,
    request: &MoveCopyFolder<'_>,
) -> trc::Result<HttpResponse> {
    let tree = ctx.folder_tree(server).await?;
    let to = resolve_folder(
        server,
        ctx,
        &tree,
        FolderSelector::from(&request.to_folder_id),
    )
    .await?
    .map(|entry| entry.node);
    let mut results = Vec::with_capacity(request.folder_ids.len());
    for id in &request.folder_ids {
        let to = match &to {
            Ok(to) => *to,
            Err(status) => {
                results.push(Err(status.clone()));
                continue;
            }
        };
        let entry = match resolve_folder(server, ctx, &tree, FolderSelector::from(id)).await? {
            Ok(entry) => entry,
            Err(status) => {
                results.push(Err(status));
                continue;
            }
        };
        let copied = copy_subtree(server, ctx, caller, &tree, entry, to).await?;
        ctx.folders_changed();
        results.push(copied);
    }
    Ok(folder_info_response(ctx, Operation::CopyFolder, results))
}

async fn copy_subtree(
    server: &Server,
    ctx: &EwsContext,
    caller: EwsCaller<'_>,
    tree: &FolderTree,
    entry: &FolderEntry,
    to: FolderNode,
) -> trc::Result<Result<Folder<'static>, Status<'static>>> {
    let Some(from) = copy_source(entry.node) else {
        return Ok(Err(write_status(
            FolderWriteError::Unsupported,
            FolderOp::Place,
        )));
    };
    if let Err(err) = mail_allowed(ctx) {
        return Ok(Err(err.status()));
    }
    if tree.in_subtree(entry.node, to) {
        return Ok(Err(write_status(FolderWriteError::Cycle, FolderOp::Place)));
    }
    let account_id = ctx.account.account_id;
    let copied = FolderCopy {
        server,
        access_token: caller.access_token,
        session_id: caller.session.session_id,
        account_id,
        scope: CopyScope::Everything,
    }
    .copy(tree, entry, from, to, &entry.name, CopyDepth::Subtree)
    .await?;
    Ok(match copied {
        Ok((root, _)) => Ok(written_folder(account_id, root, FolderVariant::of(entry))),
        Err(FolderCopyError::Folder(err)) => Err(write_status(err, FolderOp::Place)),
        Err(FolderCopyError::MailboxLimit) => Err(ItemError::MoveCopyFailed.status()),
        Err(FolderCopyError::Conflict) => Err(ItemError::Conflict.status()),
    })
}
