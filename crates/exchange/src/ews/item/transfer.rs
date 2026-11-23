/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{
    EmailIds, ItemError, MailItem, MailWrite,
    edit::{Edited, commit_edits},
    get::Target,
    may_write_mailbox, writable_mail,
    write::{Placed, Placement, destination, place_or_remove},
};
use crate::{
    ews::{
        context::{EwsCaller, EwsContext},
        folder::{cross_mailbox_status, crosses_mailbox},
        target::admitted,
    },
    folders::access::{ItemWrite, LogonAccess},
    mail::CopyOutcome,
};
use common::Server;
use email::{
    cache::{MessageCacheFetch, email::MessageCacheAccess},
    message::copy::{CopyMessageError, CopySources, EmailCopy},
};
use exchange_proto::{
    ews::types::ids::{BaseItemId, TargetFolderId},
    ids::ews::EwsObjectId,
};
#[cfg(stalwart_tests)]
use std::sync::atomic::{AtomicBool, Ordering};
use store::roaring::RoaringBitmap;
use types::keyword::Keyword;

#[cfg(stalwart_tests)]
pub static FAIL_REMOVAL: AtomicBool = AtomicBool::new(false);

pub(super) enum Destination {
    Same,
    Refused,
    Other(Box<EwsContext>),
}

struct Checked {
    slot: usize,
    item: MailItem,
    keywords: Vec<Keyword>,
    received_at: u64,
}

impl Destination {
    pub(super) async fn of(
        server: &Server,
        ctx: &EwsContext,
        id: &TargetFolderId<'_>,
    ) -> trc::Result<Self> {
        let account_id = match id {
            TargetFolderId::Folder(folder) => match EwsObjectId::decode(folder.id.as_str()) {
                Some(decoded) => decoded.account(),
                None => return Ok(Destination::Same),
            },
            TargetFolderId::Distinguished(folder) => match folder
                .mailbox
                .as_ref()
                .and_then(|mailbox| mailbox.email_address.as_deref())
                .filter(|address| !address.is_empty())
            {
                Some(address) => match ctx.account_of(server, address).await? {
                    Some(account_id) => account_id,
                    None => return Ok(Destination::Same),
                },
                None => ctx.caller.account_id(),
            },
            TargetFolderId::AddressList(_) => return Ok(Destination::Same),
        };
        if account_id == ctx.account.account_id {
            Ok(Destination::Same)
        } else if !ctx.targets_caller() && account_id != ctx.caller.account_id() {
            Ok(
                if crosses_mailbox(ctx, id) || LogonAccess::of(&ctx.caller, account_id).is_some() {
                    Destination::Refused
                } else {
                    Destination::Same
                },
            )
        } else {
            Ok(match admitted(server, ctx, account_id).await? {
                Some(destination) => Destination::Other(Box::new(destination)),
                None => Destination::Same,
            })
        }
    }
}

pub(super) async fn transfer_mail(
    server: &Server,
    ctx: &EwsContext,
    caller: EwsCaller<'_>,
    destination_ctx: &EwsContext,
    to_folder_id: &TargetFolderId<'_>,
    item_ids: &[BaseItemId<'_>],
    placement: Placement,
) -> trc::Result<Vec<Placed>> {
    let mut placed: Vec<Placed> = Vec::with_capacity(item_ids.len());
    let mut mail = 0usize;
    for id in item_ids {
        placed.push(match Target::of(id) {
            Target::Mail => {
                mail += 1;
                Ok(None)
            }
            _ => Err(cross_mailbox_status()),
        });
    }
    if mail == 0 {
        return Ok(placed);
    }
    let imap = &server.core.imap;
    let cap = match placement {
        Placement::Move => imap.max_messages_per_command,
        Placement::Copy => imap.max_messages_per_save,
    };
    let to = match destination(server, destination_ctx, to_folder_id).await? {
        Ok(to) if !may_write_mailbox(destination_ctx, to, ItemWrite::Create) => {
            Err(ItemError::Forbidden.status())
        }
        Ok(_) if mail > usize::try_from(cap).unwrap_or(usize::MAX) => {
            Err(ItemError::TooManyItems.status())
        }
        to => to,
    };
    let to = match to {
        Ok(to) => to,
        Err(status) => {
            for slot in placed.iter_mut().filter(|slot| slot.is_ok()) {
                *slot = Err(status.clone());
            }
            return Ok(placed);
        }
    };

    let source_write = match placement {
        Placement::Move => MailWrite::Move,
        Placement::Copy => MailWrite::Read,
    };
    let limits = &server.core.email.limits;
    let ids = EmailIds::load(server, ctx).await?;
    let cache = server.get_cached_messages(ctx.account.account_id).await?;
    let mut claimed = RoaringBitmap::new();
    let mut checked = Vec::with_capacity(mail);
    for (slot, (id, outcome)) in item_ids.iter().zip(placed.iter_mut()).enumerate() {
        if outcome.is_err() {
            continue;
        }
        let item = match ids
            .decode(ctx, id)
            .and_then(|item| writable_mail(ctx, &cache, item, source_write))
        {
            Ok(item) => item,
            Err(err) => {
                *outcome = Err(err.status());
                continue;
            }
        };
        let Some(message) = cache
            .email_by_id(&item.document_id)
            .filter(|message| message.has_mailbox_id(item.mailbox_id))
        else {
            *outcome = Err(ItemError::NotFound.status());
            continue;
        };
        if !claimed.insert(item.document_id) {
            *outcome = Err(ItemError::Duplicate.status());
            continue;
        }
        let keywords = cache.expand_keywords(message).collect::<Vec<_>>();
        let user_keywords = keywords
            .iter()
            .filter(|keyword| !matches!(keyword, Keyword::HasAttachment | Keyword::HasNoAttachment))
            .count();
        if limits
            .validate_keywords(
                user_keywords,
                keywords.iter().filter_map(|keyword| keyword.id().err()),
            )
            .is_err()
        {
            *outcome = Err(ItemError::KeywordLimit.status());
            continue;
        }
        checked.push(Checked {
            slot,
            item,
            keywords,
            received_at: message.received_at(),
        });
    }
    if checked.is_empty() {
        return Ok(placed);
    }

    let destination_id = destination_ctx.account.account_id;
    let destination_account = server.account(destination_id).await?;
    // SPDX-SnippetBegin
    // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
    // SPDX-License-Identifier: LicenseRef-SEL
    #[cfg(feature = "enterprise")]
    let mut tenant_budget = server.tenant_quota_budget(&destination_account).await?;
    // SPDX-SnippetEnd
    let mut sources = CopySources::new(
        ctx.account.account_id,
        checked
            .iter()
            .map(|checked| checked.item.document_id)
            .collect(),
    );
    let mut existing = Vec::new();
    let mut copied = Vec::with_capacity(checked.len());
    for checked in checked {
        let Some(source) = sources.take(server, checked.item.document_id).await? else {
            fail(&mut placed, checked.slot, ItemError::NotFound);
            continue;
        };
        match server
            .copy_message(
                source,
                &destination_account,
                // SPDX-SnippetBegin
                // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
                // SPDX-License-Identifier: LicenseRef-SEL
                #[cfg(feature = "enterprise")]
                &mut tenant_budget,
                // SPDX-SnippetEnd
                vec![to],
                checked.keywords,
                checked.received_at,
                None,
                caller.session.session_id,
            )
            .await?
        {
            Ok(_) => copied.push((checked.slot, checked.item)),
            Err(CopyMessageError::AlreadyExists(document_id)) => {
                existing.push((checked.slot, checked.item, document_id))
            }
            Err(CopyMessageError::OverQuota) => fail(&mut placed, checked.slot, ItemError::Quota),
        }
    }

    if !existing.is_empty() {
        let mut filings = existing
            .iter()
            .map(|(_, _, document_id)| *document_id)
            .collect::<Vec<_>>();
        filings.sort_unstable();
        filings.dedup();
        let filed = commit_edits(
            server,
            caller,
            destination_id,
            &filings,
            |round, document_id| {
                let Some(data) = round.cache.message_data(*document_id) else {
                    return Ok(Err(ItemError::NotFound));
                };
                if let Err(err) = round.claim(*document_id) {
                    return Ok(Err(err));
                }
                Ok(match round.edits.file_in(limits, *document_id, data, to)? {
                    CopyOutcome::Copied | CopyOutcome::AlreadyThere => Ok(Edited::Done),
                    CopyOutcome::NotInSource => Err(ItemError::NotFound),
                    CopyOutcome::MailboxLimit => Err(ItemError::MoveCopyFailed),
                })
            },
        )
        .await?;
        for (slot, item, document_id) in existing {
            match filings
                .binary_search(&document_id)
                .ok()
                .and_then(|index| filed.outcomes.get(index))
            {
                Some(Ok(_)) => copied.push((slot, item)),
                Some(Err(err)) => fail(&mut placed, slot, *err),
                None => fail(&mut placed, slot, ItemError::NotFound),
            }
        }
    }

    if placement == Placement::Move && !copied.is_empty() {
        let removed = commit_edits(
            server,
            caller,
            ctx.account.account_id,
            &copied,
            |round, (_, item)| {
                #[cfg(stalwart_tests)]
                if FAIL_REMOVAL.load(Ordering::Relaxed) {
                    return Ok(Err(ItemError::Conflict));
                }
                match writable_mail(ctx, round.cache, *item, MailWrite::Move) {
                    Ok(item) => place_or_remove(round, item, None),
                    Err(err) => Ok(Err(err)),
                }
            },
        )
        .await?;
        for ((slot, _), outcome) in copied.iter().zip(removed.outcomes) {
            if let Err(err) = outcome {
                fail(&mut placed, *slot, err);
            }
        }
    }
    Ok(placed)
}

fn fail(placed: &mut [Placed], slot: usize, err: ItemError) {
    if let Some(outcome) = placed.get_mut(slot) {
        *outcome = Err(err.status());
    }
}
