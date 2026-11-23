/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{
    context::EasContext, folder_sync::MAX_STATE_ATTEMPTS, response::EasResponse,
    sync::estimate::mail_folder,
};
use crate::{
    folders::FolderNode,
    mail::{CommitOutcome, MailEdits},
    store::FolderRef,
};
use ::email::cache::{MessageCacheFetch, email::MessageCacheAccess};
use common::{MessageStoreCache, Server};
use exchange_proto::{
    common::token::TokenBuf,
    eas::{
        commands::move_items::{MoveItem, MoveItemsRequest, MoveItemsResponse, MoveItemsResult},
        http::Command,
        status::{CommonStatus, MoveItemsStatus},
        wbxml::Decoder,
    },
    ids::eas::EasServerId,
};
use store::roaring::RoaringBitmap;

pub trait EasMoveItems: Sync + Send {
    fn eas_move_items(
        &self,
        ctx: &EasContext<'_>,
        decoder: Option<&mut Decoder<'_>>,
    ) -> impl Future<Output = trc::Result<EasResponse>> + Send;
}

enum Outcome {
    Moved { document_id: u32, to: FolderRef },
    Failed(MoveItemsStatus),
}

impl EasMoveItems for Server {
    async fn eas_move_items(
        &self,
        ctx: &EasContext<'_>,
        decoder: Option<&mut Decoder<'_>>,
    ) -> trc::Result<EasResponse> {
        let Some(decoder) = decoder else {
            return Ok(EasResponse::status(
                Command::MoveItems,
                CommonStatus::INVALID_XML.into(),
            ));
        };
        let request = match MoveItemsRequest::parse(decoder, ctx.version) {
            Ok(request) => request,
            Err(err) => {
                return Ok(EasResponse::status(
                    Command::MoveItems,
                    err.status(Command::MoveItems),
                ));
            }
        };

        let mut cache = self.get_cached_messages(ctx.account_id).await?;
        let mut outcomes = Vec::with_capacity(request.moves.len());
        let mut committed = false;
        let mut attempt = Attempt::First;
        for _ in 0..MAX_STATE_ATTEMPTS {
            outcomes.clear();
            let mut edits = MailEdits::new(ctx.account_id);
            let mut planned = RoaringBitmap::new();
            for item in &request.moves {
                let outcome = match resolve(ctx, &cache, item, attempt) {
                    Ok((document_id, _, _)) if !planned.insert(document_id) => {
                        Outcome::Failed(MoveItemsStatus::MULTIPLE_DESTINATIONS_OR_LOCKED)
                    }
                    Ok((document_id, from, to)) => match cache.message_data(document_id) {
                        Some(data) => {
                            let in_destination = data.has_mailbox_id(to.id);
                            if edits.move_to(document_id, data, from.id, to.id)?
                                || (attempt == Attempt::Retry && in_destination)
                            {
                                Outcome::Moved { document_id, to }
                            } else {
                                Outcome::Failed(MoveItemsStatus::INVALID_SOURCE)
                            }
                        }
                        None => Outcome::Failed(MoveItemsStatus::INVALID_SOURCE),
                    },
                    Err(status) => Outcome::Failed(status),
                };
                outcomes.push(outcome);
            }
            match edits
                .commit(self, &ctx.access_token, ctx.session.session_id)
                .await?
            {
                CommitOutcome::Committed(_) => {
                    committed = true;
                    break;
                }
                CommitOutcome::Conflict => {
                    attempt = Attempt::Retry;
                    cache = self.get_cached_messages(ctx.account_id).await?;
                }
            }
        }
        if !committed {
            return Ok(EasResponse::status(
                Command::MoveItems,
                CommonStatus::SERVER_ERROR_RETRY_LATER.into(),
            ));
        }

        let destinations = outcomes
            .iter()
            .map(|outcome| match outcome {
                Outcome::Moved { document_id, to } => Some(
                    EasServerId {
                        container: to.id,
                        id: *document_id,
                    }
                    .encode(),
                ),
                Outcome::Failed(_) => None,
            })
            .collect::<Vec<Option<TokenBuf>>>();
        let response = MoveItemsResponse {
            status: None,
            responses: request
                .moves
                .iter()
                .zip(outcomes.iter().zip(&destinations))
                .map(|(item, (outcome, destination))| MoveItemsResult {
                    src_msg_id: item.src_msg_id.as_ref(),
                    status: match outcome {
                        Outcome::Moved { .. } => MoveItemsStatus::SUCCESS,
                        Outcome::Failed(status) => *status,
                    },
                    dst_msg_id: destination.as_ref().map(TokenBuf::as_str),
                })
                .collect(),
        };
        Ok(EasResponse::encode(ctx.version, |encoder| {
            response.encode(encoder)
        }))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Attempt {
    First,
    Retry,
}

fn resolve(
    ctx: &EasContext<'_>,
    cache: &MessageStoreCache,
    item: &MoveItem<'_>,
    attempt: Attempt,
) -> Result<(u32, FolderRef, FolderRef), MoveItemsStatus> {
    let from = FolderNode::from_eas_collection_id(&item.src_fld_id)
        .and_then(|node| mail_folder(ctx, node))
        .filter(|folder| cache.mailboxes.index.contains_key(&folder.id))
        .ok_or(MoveItemsStatus::INVALID_SOURCE)?;
    let document_id = EasServerId::decode(&item.src_msg_id)
        .filter(|id| id.container == from.id)
        .and_then(|id| cache.email_by_id(&id.id))
        .filter(|message| attempt == Attempt::Retry || message.has_mailbox_id(from.id))
        .map(|message| message.document_id())
        .ok_or(MoveItemsStatus::INVALID_SOURCE)?;
    let to = FolderNode::from_eas_collection_id(&item.dst_fld_id)
        .and_then(|node| mail_folder(ctx, node))
        .filter(|folder| cache.mailboxes.index.contains_key(&folder.id))
        .ok_or(MoveItemsStatus::INVALID_DESTINATION)?;
    if from.id == to.id {
        return Err(MoveItemsStatus::SAME_FOLDER);
    }
    Ok((document_id, from, to))
}
