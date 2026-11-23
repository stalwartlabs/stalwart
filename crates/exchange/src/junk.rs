/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use common::{Server, auth::AccessToken};
use email::sieve::rules::{
    RuleError, SenderEntry, SenderList, SenderListKind,
    managed::{ManagedSieveScript, SaveError},
};
use exchange_proto::{
    convert::model::PropBag,
    mapi::junk_rule::{JunkLists, JunkRule},
};
use std::{cmp::Ordering, iter::Peekable};
use trc::AddContext;

const MAX_SYNC_ATTEMPTS: usize = 3;

#[derive(Debug, Default, PartialEq, Eq)]
struct SenderDelta {
    removed: Vec<u64>,
    added: Vec<String>,
}

#[derive(Default)]
struct Skipped {
    count: usize,
    first: Option<RuleError>,
}

pub(crate) fn junk_rule(props: &PropBag, account_id: u32) -> Option<JunkRule> {
    match JunkRule::from_props(props)? {
        Ok(rule) => Some(rule),
        Err(err) => {
            trc::event!(
                Sieve(trc::SieveEvent::NotSupported),
                AccountId = account_id,
                Details = "Undecodable junk e-mail rule condition",
                Reason = format!("{err:?}"),
            );
            None
        }
    }
}

pub(crate) fn junk_baseline(props: &PropBag) -> JunkLists {
    match JunkRule::from_props(props) {
        Some(Ok(JunkRule {
            is_enabled: true,
            lists,
        })) => lists,
        _ => JunkLists::default(),
    }
}

pub(crate) async fn apply_junk_rule(
    server: &Server,
    access_token: &AccessToken,
    account_id: u32,
    rule: Option<JunkRule>,
    baseline: JunkLists,
) {
    if let Some(rule) = rule
        && let Err(err) = sync_junk_rule(server, access_token, account_id, rule, baseline).await
    {
        trc::error!(err.details("Failed to apply the junk e-mail rule"));
    }
}

async fn sync_junk_rule(
    server: &Server,
    access_token: &AccessToken,
    account_id: u32,
    rule: JunkRule,
    baseline: JunkLists,
) -> trc::Result<()> {
    let JunkRule { is_enabled, lists } = rule;
    if !is_enabled {
        return Ok(());
    }
    if !lists.safe_recipients.is_empty() && lists.safe_recipients != baseline.safe_recipients {
        trc::event!(
            Sieve(trc::SieveEvent::NotSupported),
            AccountId = account_id,
            Details = "Junk e-mail safe recipients are not applied",
            Total = lists.safe_recipients.len(),
        );
    }
    let deltas = [
        (
            SenderListKind::Blocked,
            SenderDelta::between(
                &sender_list(&baseline.blocked_senders),
                &sender_list(&lists.blocked_senders),
            ),
        ),
        (
            SenderListKind::Safe,
            SenderDelta::between(
                &sender_list(&baseline.safe_senders),
                &sender_list(&lists.safe_senders),
            ),
        ),
    ];
    if deltas.iter().all(|(_, delta)| delta.is_empty()) {
        return Ok(());
    }
    for _ in 0..MAX_SYNC_ATTEMPTS {
        let mut state = server
            .managed_script_load(account_id)
            .await
            .caused_by(trc::location!())?;
        let mut skipped = Skipped::default();
        let mut changed = false;
        for (kind, delta) in &deltas {
            changed |= delta.apply(state.script.senders_mut(*kind), &mut skipped);
        }
        if !changed {
            skipped.log(account_id);
            return Ok(());
        }
        match server
            .managed_script_save(access_token, account_id, state)
            .await
            .caused_by(trc::location!())?
        {
            Ok(None) => {
                skipped.log(account_id);
                return Ok(());
            }
            Ok(Some(_)) => {
                skipped.log(account_id);
                return Ok(());
            }
            Err(SaveError::Conflict) => {}
            Err(SaveError::Invalid(err)) => return Err(invalid(account_id, err)),
        }
    }
    Err(trc::StoreEvent::AssertValueFailed
        .into_err()
        .account_id(account_id)
        .details("Junk e-mail rule save kept conflicting")
        .caused_by(trc::location!()))
}

fn sender_list(entries: &[String]) -> SenderList {
    let mut list = SenderList::default();
    for entry in entries {
        let _ = list.insert(entry);
    }
    list
}

impl SenderDelta {
    fn between(baseline: &SenderList, current: &SenderList) -> Self {
        let mut delta = SenderDelta::default();
        let mut baseline = baseline.iter().peekable();
        let mut current = current.iter().peekable();
        while let Some(order) = next_order(&mut baseline, &mut current) {
            match order {
                Ordering::Less => {
                    if let Some(entry) = baseline.next() {
                        delta.removed.push(entry.id);
                    }
                }
                Ordering::Greater => {
                    if let Some(entry) = current.next() {
                        delta.added.push(entry.entry.clone());
                    }
                }
                Ordering::Equal => {
                    baseline.next();
                    current.next();
                }
            }
        }
        delta
    }

    fn is_empty(&self) -> bool {
        self.removed.is_empty() && self.added.is_empty()
    }

    fn apply(&self, list: &mut SenderList, skipped: &mut Skipped) -> bool {
        let mut changed = false;
        for id in &self.removed {
            changed |= list.remove(*id).is_some();
        }
        for entry in &self.added {
            match list.insert(entry) {
                Ok(_) => changed = true,
                Err(RuleError::EntryExists(_)) => {}
                Err(err) => skipped.record(err),
            }
        }
        changed
    }
}

fn next_order<'x, B, C>(baseline: &mut Peekable<B>, current: &mut Peekable<C>) -> Option<Ordering>
where
    B: Iterator<Item = &'x SenderEntry>,
    C: Iterator<Item = &'x SenderEntry>,
{
    match (baseline.peek(), current.peek()) {
        (Some(old), Some(new)) => Some(old.entry.cmp(&new.entry)),
        (Some(_), None) => Some(Ordering::Less),
        (None, Some(_)) => Some(Ordering::Greater),
        (None, None) => None,
    }
}

impl Skipped {
    fn record(&mut self, err: RuleError) {
        self.count += 1;
        self.first.get_or_insert(err);
    }

    fn log(self, account_id: u32) {
        if let Some(err) = self.first {
            trc::event!(
                Sieve(trc::SieveEvent::NotSupported),
                AccountId = account_id,
                Details = "Junk e-mail list entries skipped",
                Total = self.count,
                Reason = err.to_string(),
            );
        }
    }
}

fn invalid(account_id: u32, err: RuleError) -> trc::Error {
    trc::StoreEvent::UnexpectedError
        .into_err()
        .account_id(account_id)
        .reason(err)
        .caused_by(trc::location!())
}

#[cfg(all(test, stalwart_tests))]
#[rustfmt::skip]
#[path = "../../../../stalwart-tests/unit/exchange/src/junk/tests.rs"]
mod tests;
