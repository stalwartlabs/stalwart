/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::super::{
    EmailIds, ItemError, MailItem, MailWrite,
    create::{Stored, Training, ingest_error, save},
    edit::{Edited, commit_edits, write_object},
    mail_allowed,
    props::is_carried_key,
    writable_mail,
};
use crate::{
    cache::ExchangeCacheFetch,
    ews::context::{EwsCaller, EwsContext},
    mail::{FlagOutcome, stored_blob_hash},
    mapi::emsmdb::message::{
        attach_row::{attachment_entry, is_attachment_entry},
        object_row::{decode_property, encode_property},
    },
    store::{
        ExchangeProperty,
        account::ExchangeAccountStore,
        object::{ExchangeObject, ExchangeObjectStore, ReplacedEmail, StoredPlacement},
    },
};
use common::Server;
use email::{
    cache::{MessageCacheFetch, email::MessageCacheAccess},
    message::{
        ingest::{IngestEmail, IngestSource},
        messagedata::{KEYWORD_BITS, SERVER_SET_KEYWORDS},
    },
};
use exchange_proto::ews::{bulk::RawProperty, types::ids::ItemId};
use mail_parser::MessageParser;
use smallvec::SmallVec;
use trc::AddContext;
use types::{blob_hash::BlobHash, collection::Collection, keyword::Keyword};

const MAX_ATTEMPTS: usize = 5;

pub(super) struct EmailRecord<'x> {
    pub raw: &'x [u8],
    pub received_at: Option<u64>,
    pub keywords: Vec<Keyword>,
    pub carried: Vec<ExchangeProperty>,
}

impl<'x> EmailRecord<'x> {
    pub fn new(
        raw: &'x [u8],
        received_at: Option<i64>,
        keywords: &[&str],
        properties: &[RawProperty<'_>],
    ) -> Result<Self, ItemError> {
        let mut carried = Vec::with_capacity(properties.len());
        for property in properties {
            if is_attachment_entry(property.key) {
                carried.push(
                    attachment_entry(property.key, property.value).ok_or(ItemError::CorruptData)?,
                );
                continue;
            }
            let (key, value) =
                decode_property(property.key, property.value).ok_or(ItemError::CorruptData)?;
            if is_carried_key(key.as_ref()) {
                carried.push(encode_property(key.as_ref(), &value));
            }
        }
        carried.sort_by(|a, b| a.key.cmp(&b.key));
        carried.dedup_by(|a, b| a.key == b.key);
        Ok(EmailRecord {
            raw,
            received_at: received_at.and_then(|seconds| u64::try_from(seconds).ok()),
            keywords: Keyword::unique(keywords.iter().map(|name| Keyword::parse(name)).filter(
                |keyword| {
                    !matches!(keyword.id(), Ok(id)
                            if 1u32.checked_shl(id).unwrap_or_default() & SERVER_SET_KEYWORDS != 0)
                },
            )),
            carried,
        })
    }

    fn system_bits(&self) -> u32 {
        self.keywords
            .iter()
            .filter_map(|keyword| keyword.id().ok())
            .fold(0, |bits, id| {
                bits | 1u32.checked_shl(id).unwrap_or_default()
            })
            & KEYWORD_BITS
    }
}

pub(super) async fn create_email(
    server: &Server,
    ctx: &EwsContext,
    caller: EwsCaller<'_>,
    ids: &EmailIds,
    mailbox_id: u32,
    record: EmailRecord<'_>,
) -> trc::Result<Result<ItemId<'static>, ItemError>> {
    if let Err(err) = mail_allowed(ctx) {
        return Ok(Err(err));
    }
    if record.raw.len() > server.core.email.mail_max_size {
        return Ok(Err(ItemError::TooLarge));
    }
    save(
        server,
        ctx,
        caller,
        ids,
        mailbox_id,
        record.raw,
        Stored {
            keywords: record.keywords,
            categories: Default::default(),
            received_at: record.received_at,
            carried: record.carried,
            training: Training::InJunk,
        },
    )
    .await
}

pub(super) async fn update_email(
    server: &Server,
    ctx: &EwsContext,
    caller: EwsCaller<'_>,
    ids: &EmailIds,
    id: &ItemId<'_>,
    mailbox_id: u32,
    record: &EmailRecord<'_>,
) -> trc::Result<Result<ItemId<'static>, ItemError>> {
    let account_id = ids.account_id();
    let cache = server.get_cached_messages(account_id).await?;
    let item = match ids.resolve_item_id(ctx, &cache, id) {
        Ok(item) => MailItem {
            mailbox_id,
            document_id: item.document_id,
        },
        Err(ItemError::Forbidden) => return Ok(Err(ItemError::NotFound)),
        Err(err) => return Ok(Err(err)),
    };
    if !cache
        .message_data(item.document_id)
        .is_some_and(|data| data.has_mailbox_id(mailbox_id))
    {
        return Ok(Err(ItemError::NotFound));
    }
    if let Err(err) = writable_mail(ctx, &cache, item, MailWrite::Edit) {
        return Ok(Err(err));
    }
    if record.raw.len() > server.core.email.mail_max_size {
        return Ok(Err(ItemError::TooLarge));
    }
    if stored_blob_hash(server, account_id, item.document_id).await?
        == Some(BlobHash::generate(record.raw))
    {
        update_state(server, caller, ids, item, record).await
    } else {
        replace(server, ctx, caller, ids, item, record).await
    }
}

async fn update_state(
    server: &Server,
    caller: EwsCaller<'_>,
    ids: &EmailIds,
    item: MailItem,
    record: &EmailRecord<'_>,
) -> trc::Result<Result<ItemId<'static>, ItemError>> {
    let account_id = ids.account_id();
    let limits = &server.core.email.limits;
    let committed = commit_edits(server, caller, account_id, &[item], |round, item| {
        if let Err(err) = round.claim(item.document_id) {
            return Ok(Err(err));
        }
        let Some(data) = round
            .cache
            .message_data(item.document_id)
            .filter(|data| data.has_mailbox_id(item.mailbox_id))
        else {
            return Ok(Err(ItemError::NotFound));
        };
        Ok(
            match round
                .edits
                .replace_keywords(limits, item.document_id, &data, &record.keywords)?
            {
                FlagOutcome::Changed => Ok(Edited::Written(*item)),
                FlagOutcome::Unchanged => Ok(Edited::Unchanged(*item, data.change_id)),
                FlagOutcome::KeywordLimit => Err(ItemError::KeywordLimit),
            },
        )
    })
    .await?;
    let keywords_change = match committed.outcomes.first() {
        Some(Ok(edited)) => committed.change_id_of(*edited).map(|(_, change)| change),
        Some(Err(err)) => return Ok(Err(*err)),
        None => None,
    };
    let carried = &record.carried;
    let object_change = match write_object(server, caller, account_id, item, None, |object| {
        if object.properties == *carried {
            false
        } else {
            object.properties.clone_from(carried);
            true
        }
    })
    .await?
    {
        Ok(change) => change,
        Err(err) => return Ok(Err(err)),
    };
    Ok(Ok(ids.item_id(
        item,
        keywords_change.max(object_change).unwrap_or_default(),
    )))
}

async fn replace(
    server: &Server,
    ctx: &EwsContext,
    caller: EwsCaller<'_>,
    ids: &EmailIds,
    item: MailItem,
    record: &EmailRecord<'_>,
) -> trc::Result<Result<ItemId<'static>, ItemError>> {
    let account_id = ids.account_id();
    let document_id = item.document_id;
    let owner = server
        .exchange_quota_owner(caller.access_token, account_id)
        .await?;
    let target_token = server
        .exchange_target_token(caller.access_token, account_id)
        .await?;
    let parsed = MessageParser::new().parse(record.raw);
    let extra = record
        .keywords
        .iter()
        .filter(|keyword| keyword.id().is_err())
        .cloned()
        .collect::<SmallVec<[Keyword; 4]>>();
    let wanted = record.system_bits() & !SERVER_SET_KEYWORDS;
    let count = wanted.count_ones() as usize + extra.len();
    for _ in 0..MAX_ATTEMPTS {
        let cache = server.get_cached_messages(account_id).await?;
        let Some(data) = cache
            .message_data(document_id)
            .filter(|data| data.has_mailbox_id(item.mailbox_id))
        else {
            return Ok(Err(ItemError::NotFound));
        };
        if let Err(err) = writable_mail(ctx, &cache, item, MailWrite::Edit) {
            return Ok(Err(err));
        }
        if server
            .core
            .email
            .limits
            .validate_keyword_change(data.keyword_count(), count)
            .is_err()
        {
            return Ok(Err(ItemError::KeywordLimit));
        }
        let stored = data.keywords & KEYWORD_BITS & !SERVER_SET_KEYWORDS;
        let exchange = server.get_cached_exchange(account_id).await?;
        let identity = StoredPlacement {
            container: item.mailbox_id,
            item: exchange.email_item(item.mailbox_id, document_id),
        };
        let object = if exchange.has_object(Collection::Email, document_id) {
            server
                .exchange_object(account_id, Collection::Email, document_id)
                .await
                .caused_by(trc::location!())?
        } else {
            None
        };
        match server
            .replace_email(
                IngestEmail {
                    raw_message: record.raw,
                    blob_hash: None,
                    message: parsed.as_ref(),
                    access_token: target_token.as_ref().unwrap_or(caller.access_token),
                    mailbox_ids: Vec::new(),
                    keywords: Vec::new(),
                    received_at: Some(record.received_at.unwrap_or(data.received_at)),
                    source: IngestSource::Jmap {
                        train_classifier: false,
                    },
                    metadata: None,
                    session_id: caller.session.session_id,
                },
                caller.access_token.changed_by(),
                owner,
                ReplacedEmail {
                    document_id,
                    data: &data,
                    identity,
                    alias: exchange.alias_of(document_id).map(StoredPlacement::from),
                    object: object.as_ref(),
                    added_keywords: wanted & !stored,
                    removed_keywords: stored & !wanted,
                    keywords_extra: Some(&extra),
                },
                (!record.carried.is_empty()).then(|| ExchangeObject {
                    properties: record.carried.clone(),
                    conflict: None,
                }),
                server.core.exchange.max_object_size,
            )
            .await
        {
            Ok(email) => {
                return Ok(Ok(ids.identity_item_id(
                    item.mailbox_id,
                    identity.item,
                    email.change_id,
                )));
            }
            Err(err) if err.is_assertion_failure() => {}
            Err(err) => return ingest_error(err).map(Err),
        }
    }
    Ok(Err(ItemError::Conflict))
}
