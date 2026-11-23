/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{EmailIds, ItemError, write::destination};
use crate::{
    ews::{
        context::{EwsCaller, EwsContext},
        reply::{RESPONSE_CAPACITY, ews_response},
    },
    submit::{
        AfterSend, DeliveryReport, ExchangeSubmit, Outgoing, Recipients, Submission, SubmitError,
        SubmitOptions,
    },
};
use common::Server;
use email::cache::{MessageCacheFetch, email::MessageCacheAccess, mailbox::MailboxCacheAccess};
use exchange_proto::ews::{
    MessageResult, Operation, Status,
    requests::item::SendItem,
    responses::folder::EmptyMessage,
    schema::{DistinguishedFolderName, ResponseCode},
    types::ids::{BaseItemId, DistinguishedFolderId, TargetFolderId},
};
use http_proto::HttpResponse;
use store::roaring::RoaringBitmap;
use types::special_use::SpecialUse;

const NO_FOLDER: &str = "The account has no folder for this operation.";
const FORBIDDEN: &str = "The account is not allowed to send mail.";
const TOO_LARGE: &str = "The message exceeds the maximum message size.";
const MALFORMED: &str = "The message could not be parsed for sending.";
const NO_RECIPIENTS: &str = "The message has no recipients.";
const SEND_AS_DENIED: &str = "The sender address does not belong to the account.";
const NOT_SENDABLE: &str = "The message cannot be sent.";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum SubmitSource {
    Composed,
    Stored,
}

pub(crate) async fn send_item(
    server: &Server,
    ctx: &EwsContext,
    caller: EwsCaller<'_>,
    request: &SendItem<'_>,
) -> trc::Result<HttpResponse> {
    let account_id = ctx.account.account_id;
    if !ctx.access.sends_as_owner() {
        let mut out = Vec::with_capacity(RESPONSE_CAPACITY);
        let mut messages = ctx.envelope(&mut out).shape_a(Operation::SendItem);
        for _ in &request.item_ids {
            messages.message(&MessageResult::<EmptyMessage> {
                status: ItemError::Forbidden.status(),
                body: None,
            });
        }
        messages.finish();
        return Ok(ews_response(out));
    }
    let saved = match (request.save_item_to_folder, &request.saved_item_folder_id) {
        (false, _) => Ok(None),
        (true, Some(id)) => sent_destination(server, ctx, id).await?.map(Some),
        (true, None) => default_folder(server, account_id, SpecialUse::Sent)
            .await?
            .map(Some),
    };
    let ids = EmailIds::load(server, ctx).await?;
    let mut sent = RoaringBitmap::new();
    let mut statuses = Vec::with_capacity(request.item_ids.len());
    for id in &request.item_ids {
        statuses.push(match &saved {
            Ok(saved) => match send_one(server, ctx, caller, &ids, id, *saved, &mut sent).await? {
                Ok(()) => Status::SUCCESS,
                Err(status) => status,
            },
            Err(status) => status.clone(),
        });
    }

    let mut out = Vec::with_capacity(RESPONSE_CAPACITY);
    let mut messages = ctx.envelope(&mut out).shape_a(Operation::SendItem);
    for status in statuses {
        messages.message(&MessageResult::<EmptyMessage> { status, body: None });
    }
    messages.finish();
    Ok(ews_response(out))
}

async fn send_one(
    server: &Server,
    ctx: &EwsContext,
    caller: EwsCaller<'_>,
    ids: &EmailIds,
    id: &BaseItemId<'_>,
    saved: Option<u32>,
    sent: &mut RoaringBitmap,
) -> trc::Result<Result<(), Status<'static>>> {
    let cache = server.get_cached_messages(ctx.account.account_id).await?;
    let item = match ids.resolve(ctx, &cache, id) {
        Ok(item) => item,
        Err(err) => return Ok(Err(err.status())),
    };
    if !sent.insert(item.document_id) {
        return Ok(Err(ItemError::Duplicate.status()));
    }
    let Some(data) = cache.message_data(item.document_id) else {
        return Ok(Err(ItemError::NotFound.status()));
    };
    let after = match saved {
        Some(to) if to != item.mailbox_id => AfterSend::MoveTo {
            from: item.mailbox_id,
            to,
            alias: None,
        },
        Some(_) => AfterSend::Keep,
        None => AfterSend::Delete {
            from: item.mailbox_id,
        },
    };
    let submitted = server
        .submit(Submission {
            access_token: caller.access_token,
            account_id: ctx.account.account_id,
            instance: &caller.session.instance,
            session_id: caller.session.session_id,
            message: Outgoing::Stored {
                document_id: item.document_id,
                data,
                after,
            },
            recipients: Recipients::Headers,
            options: SubmitOptions {
                delivery_report: DeliveryReport::FromMessage,
                ..Default::default()
            },
        })
        .await?;
    Ok(match submitted {
        Ok(submitted) => {
            if let Some(Err(err)) = submitted.after_send {
                trc::error!(err.caused_by(trc::location!()));
            }
            Ok(())
        }
        Err(err) => Err(submit_status(err, SubmitSource::Stored)),
    })
}

pub(super) async fn default_folder(
    server: &Server,
    account_id: u32,
    role: SpecialUse,
) -> trc::Result<Result<u32, Status<'static>>> {
    Ok(server
        .get_cached_messages(account_id)
        .await?
        .mailbox_by_role(&role)
        .map(|mailbox| mailbox.document_id)
        .ok_or_else(|| Status::error(ResponseCode::ErrorFolderNotFound, NO_FOLDER)))
}

pub(super) async fn sent_destination(
    server: &Server,
    ctx: &EwsContext,
    id: &TargetFolderId<'_>,
) -> trc::Result<Result<u32, Status<'static>>> {
    match id {
        TargetFolderId::Distinguished(DistinguishedFolderId {
            name: DistinguishedFolderName::Sentitems,
            mailbox,
            ..
        }) if !ctx.targets_caller()
            && mailbox
                .as_ref()
                .and_then(|mailbox| mailbox.email_address.as_deref())
                .is_none_or(str::is_empty) =>
        {
            default_folder(server, ctx.account.account_id, SpecialUse::Sent).await
        }
        _ => destination(server, ctx, id).await,
    }
}

pub(super) fn submit_status(err: SubmitError, source: SubmitSource) -> Status<'static> {
    match err {
        SubmitError::Forbidden => Status::error(ResponseCode::ErrorAccessDenied, FORBIDDEN),
        SubmitError::NotFound => ItemError::NotFound.status(),
        SubmitError::TooLarge { .. } => {
            Status::error(ResponseCode::ErrorMessageSizeExceeded, TOO_LARGE)
        }
        SubmitError::Malformed => Status::error(
            match source {
                SubmitSource::Composed => ResponseCode::ErrorInvalidRequest,
                SubmitSource::Stored => ResponseCode::ErrorCorruptData,
            },
            MALFORMED,
        ),
        SubmitError::NoRecipients => {
            Status::error(ResponseCode::ErrorInvalidRecipients, NO_RECIPIENTS)
        }
        SubmitError::Recipients(rejected) => Status::error(
            ResponseCode::ErrorInvalidRecipients,
            rejected.into_iter().next().map_or_else(
                || NO_RECIPIENTS.to_string(),
                |first| first.reply.into_string(),
            ),
        ),
        SubmitError::SendAsDenied => Status::error(ResponseCode::ErrorSendAsDenied, SEND_AS_DENIED),
        SubmitError::Sender(reply) | SubmitError::Rejected(reply) => Status::error(
            ResponseCode::ErrorMessageSubmissionBlocked,
            reply.into_string(),
        ),
        SubmitError::AlreadySent | SubmitError::InProgress => {
            Status::error(ResponseCode::ErrorInvalidOperation, NOT_SENDABLE)
        }
    }
}
