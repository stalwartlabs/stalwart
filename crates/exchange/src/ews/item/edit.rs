/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{ItemError, MailItem, create::ingest_error};
use crate::{
    cache::ExchangeCacheFetch,
    ews::context::EwsCaller,
    mail::{CommitOutcome, MailEdits},
    store::{
        account::ExchangeAccountStore,
        object::{
            ExchangeObject, ExchangeObjectStore, ExchangeObjectWrite, ObjectVersion, OwnerStamp,
        },
    },
};
use common::{MessageStoreCache, Server};
use email::cache::{MessageCacheFetch, email::MessageCacheAccess};
use store::{
    roaring::RoaringBitmap,
    write::{BatchBuilder, PendingId},
};
use trc::AddContext;
use types::collection::{Collection, SyncCollection};

const MAX_ATTEMPTS: usize = 5;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Attempt {
    First,
    Retry,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Edited {
    Written(MailItem),
    Unchanged(MailItem, u64),
    Done,
}

pub(crate) struct EditRound<'c> {
    pub edits: MailEdits,
    pub cache: &'c MessageStoreCache,
    pub attempt: Attempt,
    account_id: u32,
    planned: RoaringBitmap,
    previous: &'c RoaringBitmap,
}

#[derive(Debug)]
pub(crate) struct CarriedEdit {
    pub key: Vec<u8>,
    pub value: Option<Vec<u8>>,
}

pub(crate) struct Committed {
    pub outcomes: Vec<Result<Edited, ItemError>>,
    pub change_id: Option<u64>,
}

impl<'c> EditRound<'c> {
    pub fn new(
        cache: &'c MessageStoreCache,
        attempt: Attempt,
        account_id: u32,
        previous: &'c RoaringBitmap,
    ) -> Self {
        EditRound {
            edits: MailEdits::new(account_id),
            cache,
            attempt,
            account_id,
            planned: RoaringBitmap::new(),
            previous,
        }
    }

    pub fn claim(&mut self, document_id: u32) -> Result<(), ItemError> {
        if self.planned.insert(document_id) {
            Ok(())
        } else {
            Err(ItemError::Duplicate)
        }
    }

    pub fn planned_before(&self, document_id: u32) -> bool {
        self.attempt == Attempt::Retry && self.previous.contains(document_id)
    }

    pub fn scratch_edits(&self) -> MailEdits {
        MailEdits::new(self.account_id)
    }
}

impl Committed {
    pub fn change_id_of(&self, edited: Edited) -> Option<(MailItem, u64)> {
        match edited {
            Edited::Written(item) => Some((item, self.change_id.unwrap_or_default())),
            Edited::Unchanged(item, change_id) => Some((item, change_id)),
            Edited::Done => None,
        }
    }
}

pub(crate) async fn commit_edits<T>(
    server: &Server,
    caller: EwsCaller<'_>,
    account_id: u32,
    items: &[T],
    mut plan: impl FnMut(&mut EditRound<'_>, &T) -> trc::Result<Result<Edited, ItemError>>,
) -> trc::Result<Committed> {
    let mut cache = server.get_cached_messages(account_id).await?;
    let mut attempt = Attempt::First;
    let mut previous = RoaringBitmap::new();
    let mut outcomes = Vec::with_capacity(items.len());
    for _ in 0..MAX_ATTEMPTS {
        let mut round = EditRound::new(&cache, attempt, account_id, &previous);
        outcomes.clear();
        for item in items {
            outcomes.push(plan(&mut round, item)?);
        }
        let EditRound { mut edits, .. } = round;
        let touched = edits.take_touched();
        match edits
            .commit(server, caller.access_token, caller.session.session_id)
            .await?
        {
            CommitOutcome::Committed(change_id) => {
                return Ok(Committed {
                    outcomes,
                    change_id,
                });
            }
            CommitOutcome::Conflict => {
                previous |= touched;
                attempt = Attempt::Retry;
                cache = server.get_cached_messages(account_id).await?;
            }
        }
    }
    Ok(Committed {
        outcomes: outcomes
            .into_iter()
            .map(|outcome| outcome.and(Err(ItemError::Conflict)))
            .collect(),
        change_id: None,
    })
}

pub(crate) async fn write_carried(
    server: &Server,
    caller: EwsCaller<'_>,
    account_id: u32,
    item: MailItem,
    expected_change: Option<u64>,
    edits: &[CarriedEdit],
) -> trc::Result<Result<Option<u64>, ItemError>> {
    write_object(
        server,
        caller,
        account_id,
        item,
        expected_change,
        |object| apply_carried(object, edits),
    )
    .await
}

pub(crate) async fn write_object(
    server: &Server,
    caller: EwsCaller<'_>,
    account_id: u32,
    item: MailItem,
    expected_change: Option<u64>,
    apply: impl Fn(&mut ExchangeObject) -> bool,
) -> trc::Result<Result<Option<u64>, ItemError>> {
    let document_id = item.document_id;
    let owner = server
        .exchange_quota_owner(caller.access_token, account_id)
        .await?;
    let max_size = server.core.exchange.max_object_size;
    for _ in 0..MAX_ATTEMPTS {
        let cache = server.get_cached_messages(account_id).await?;
        let Some(data) = cache
            .message_data(document_id)
            .filter(|data| data.has_mailbox_id(item.mailbox_id))
        else {
            return Ok(Err(ItemError::NotFound));
        };
        if expected_change.is_some_and(|change_id| change_id != data.change_id) {
            return Ok(Err(ItemError::Stale));
        }
        let exchange = server.get_cached_exchange(account_id).await?;
        let previous = if exchange.has_object(Collection::Email, document_id) {
            server
                .exchange_object(account_id, Collection::Email, document_id)
                .await
                .caused_by(trc::location!())?
        } else {
            None
        };
        let mut next = previous
            .as_ref()
            .map(|previous| previous.deserialize::<ExchangeObject>())
            .transpose()?
            .unwrap_or_default();
        if !apply(&mut next) {
            return Ok(Ok(None));
        }
        let mut batch = BatchBuilder::new();
        if let Err(err) = (ExchangeObjectWrite {
            owner,
            collection: Collection::Email,
            document_id: PendingId::Assigned(document_id),
            stamp: OwnerStamp::Email {
                thread_id: data.thread_id,
            },
            version: ObjectVersion::Server,
            previous: previous.as_ref(),
            next: Some(next),
            max_size,
        })
        .build(&mut batch)
        {
            return ingest_error(err).map(Err);
        }
        match server.commit_batch(batch).await {
            Ok(assigned) => {
                server.mark_exchange_stale(account_id);
                return Ok(Ok(assigned.change_id(account_id, SyncCollection::Email)));
            }
            Err(err) if err.is_assertion_failure() => server.mark_exchange_stale(account_id),
            Err(err) => return ingest_error(err).map(Err),
        }
    }
    Ok(Err(ItemError::Conflict))
}

pub(crate) fn apply_carried(object: &mut ExchangeObject, edits: &[CarriedEdit]) -> bool {
    let mut changed = false;
    for edit in edits {
        changed |= match &edit.value {
            Some(value) if object.property(&edit.key) != Some(value.as_slice()) => {
                object.set_property(edit.key.clone(), value.clone());
                true
            }
            Some(_) => false,
            None => object.remove_property(&edit.key).is_some(),
        };
    }
    changed
}
