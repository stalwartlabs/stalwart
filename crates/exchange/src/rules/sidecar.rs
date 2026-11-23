/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::store::account_key;
use common::Server;
use exchange_proto::rules::{DeliverMode, MapiRule, RedirectKind, STORED_ID_BASE};
use store::{
    Deserialize, Serialize,
    write::{
        Archive, ArchiveBytes, ArchiveCompression, Archiver, BatchBuilder, MergeResult,
        metadata::ExchangeClass,
    },
};
use trc::AddContext;
use types::collection::Collection;

#[derive(
    rkyv::Archive, rkyv::Deserialize, rkyv::Serialize, Debug, Default, Clone, PartialEq, Eq,
)]
pub struct OutlookRules {
    pub next_stored: u64,
    pub rules: Vec<OutlookRule>,
}

#[derive(rkyv::Archive, rkyv::Deserialize, rkyv::Serialize, Debug, Clone, PartialEq, Eq)]
pub struct OutlookRule {
    pub id: u64,
    pub sequence: i32,
    pub state: u32,
    pub name: String,
    pub link: RuleLink,
    pub mapi: Option<StoredMapi>,
    pub pending: Option<u64>,
}

#[derive(rkyv::Archive, rkyv::Deserialize, rkyv::Serialize, Debug, Clone, PartialEq, Eq)]
pub enum RuleLink {
    Core {
        hash: u64,
        redirects: Vec<StoredRedirect>,
        reply_template: Option<String>,
    },
    StoredOnly,
    Delegate {
        has_core: bool,
        mode: StoredDeliverMode,
        recipients: Vec<StoredRecipient>,
    },
}

#[derive(rkyv::Archive, rkyv::Deserialize, rkyv::Serialize, Debug, Clone, Copy, PartialEq, Eq)]
pub enum StoredDeliverMode {
    DelegatesOnly,
    DelegatesAndMe,
    DelegatesAndSendInformationToMe,
    NoForward,
}

#[derive(rkyv::Archive, rkyv::Deserialize, rkyv::Serialize, Debug, Clone, Copy, PartialEq, Eq)]
pub enum StoredRedirectKind {
    Forward,
    ForwardAsAttachment,
    Redirect,
}

#[derive(rkyv::Archive, rkyv::Deserialize, rkyv::Serialize, Debug, Clone, PartialEq, Eq)]
pub struct StoredMapi {
    pub provider: String,
    pub provider_data: Vec<u8>,
    pub user_flags: u32,
    pub level: u32,
    pub condition: Vec<u8>,
    pub actions: Vec<u8>,
}

#[derive(rkyv::Archive, rkyv::Deserialize, rkyv::Serialize, Debug, Clone, PartialEq, Eq)]
pub struct StoredRedirect {
    pub address: String,
    pub kind: StoredRedirectKind,
}

#[derive(rkyv::Archive, rkyv::Deserialize, rkyv::Serialize, Debug, Clone, PartialEq, Eq)]
pub struct StoredRecipient {
    pub principal_id: u32,
    pub address: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SidecarChange {
    Upsert(OutlookRule),
    AddPending(OutlookRule),
    AddStored(OutlookRule),
    Remove(u64),
}

impl ArchiveCompression for OutlookRules {}

impl OutlookRules {
    pub fn rule(&self, id: u64) -> Option<&OutlookRule> {
        self.rules
            .binary_search_by_key(&id, |rule| rule.id)
            .ok()
            .and_then(|index| self.rules.get(index))
    }

    pub fn apply(&mut self, changes: &[SidecarChange]) -> bool {
        let mut changed = false;
        for change in changes {
            match change {
                SidecarChange::Upsert(rule) | SidecarChange::AddPending(rule) => {
                    let insert_only = matches!(change, SidecarChange::AddPending(_));
                    match self
                        .rules
                        .binary_search_by_key(&rule.id, |stored| stored.id)
                    {
                        Ok(index) => {
                            if let Some(stored) = self.rules.get_mut(index)
                                && stored != rule
                                && !(insert_only && stored.pending.is_none())
                            {
                                *stored = rule.clone();
                                changed = true;
                            }
                        }
                        Err(index) => {
                            self.rules.insert(index, rule.clone());
                            changed = true;
                        }
                    }
                }
                SidecarChange::AddStored(rule) => {
                    let id = STORED_ID_BASE | self.next_stored;
                    self.next_stored = self.next_stored.wrapping_add(1) & (STORED_ID_BASE - 1);
                    let rule = OutlookRule { id, ..rule.clone() };
                    match self.rules.binary_search_by_key(&id, |stored| stored.id) {
                        Ok(index) => {
                            if let Some(stored) = self.rules.get_mut(index) {
                                *stored = rule;
                            }
                        }
                        Err(index) => self.rules.insert(index, rule),
                    }
                    changed = true;
                }
                SidecarChange::Remove(id) => {
                    if let Ok(index) = self.rules.binary_search_by_key(id, |stored| stored.id) {
                        self.rules.remove(index);
                        changed = true;
                    }
                }
            }
        }
        changed
    }
}

impl ArchivedOutlookRules {
    pub fn forwards_to(&self, principal_id: u32) -> bool {
        self.rules.iter().any(|rule| {
            matches!(
                &rule.link,
                ArchivedRuleLink::Delegate { has_core: true, recipients, .. }
                    if rule.pending.is_none() && recipients.iter().any(|recipient| recipient.principal_id == principal_id)
            )
        })
    }
}

impl ArchivedOutlookRule {
    fn is_listed(&self) -> bool {
        self.pending.is_none()
            && (self.mapi.is_some()
                || !matches!(
                    self.link,
                    ArchivedRuleLink::Delegate {
                        has_core: false,
                        ..
                    }
                ))
    }
}

impl OutlookRule {
    pub fn mapi(&self) -> Option<Box<MapiRule>> {
        self.mapi.as_ref().map(|mapi| {
            Box::new(MapiRule {
                provider: mapi.provider.as_str().into(),
                provider_data: mapi.provider_data.as_slice().into(),
                user_flags: mapi.user_flags,
                level: mapi.level,
                condition: mapi.condition.as_slice().into(),
                actions: mapi.actions.as_slice().into(),
            })
        })
    }
}

impl StoredMapi {
    pub fn new(mapi: &MapiRule) -> Self {
        StoredMapi {
            provider: mapi.provider.to_string(),
            provider_data: mapi.provider_data.to_vec(),
            user_flags: mapi.user_flags,
            level: mapi.level,
            condition: mapi.condition.to_vec(),
            actions: mapi.actions.to_vec(),
        }
    }
}

impl StoredRedirect {
    pub fn new(address: &str, kind: RedirectKind) -> Self {
        StoredRedirect {
            address: address.to_string(),
            kind: match kind {
                RedirectKind::Forward => StoredRedirectKind::Forward,
                RedirectKind::ForwardAsAttachment => StoredRedirectKind::ForwardAsAttachment,
                RedirectKind::Redirect => StoredRedirectKind::Redirect,
            },
        }
    }

    pub fn kind(&self) -> RedirectKind {
        match self.kind {
            StoredRedirectKind::Forward => RedirectKind::Forward,
            StoredRedirectKind::ForwardAsAttachment => RedirectKind::ForwardAsAttachment,
            StoredRedirectKind::Redirect => RedirectKind::Redirect,
        }
    }
}

impl StoredDeliverMode {
    pub fn new(mode: DeliverMode) -> Self {
        match mode {
            DeliverMode::DelegatesOnly => StoredDeliverMode::DelegatesOnly,
            DeliverMode::DelegatesAndMe => StoredDeliverMode::DelegatesAndMe,
            DeliverMode::DelegatesAndSendInformationToMe => {
                StoredDeliverMode::DelegatesAndSendInformationToMe
            }
            DeliverMode::NoForward => StoredDeliverMode::NoForward,
        }
    }

    pub fn mode(self) -> DeliverMode {
        match self {
            StoredDeliverMode::DelegatesOnly => DeliverMode::DelegatesOnly,
            StoredDeliverMode::DelegatesAndMe => DeliverMode::DelegatesAndMe,
            StoredDeliverMode::DelegatesAndSendInformationToMe => {
                DeliverMode::DelegatesAndSendInformationToMe
            }
            StoredDeliverMode::NoForward => DeliverMode::NoForward,
        }
    }
}

pub async fn read_sidecar(server: &Server, account_id: u32) -> trc::Result<OutlookRules> {
    match stored_sidecar(server, account_id).await? {
        Some(stored) => stored.deserialize::<OutlookRules>(),
        None => Ok(OutlookRules::default()),
    }
}

pub async fn sidecar_has_rules(server: &Server, account_id: u32) -> trc::Result<bool> {
    match stored_sidecar(server, account_id).await? {
        Some(stored) => Ok(stored
            .unarchive::<OutlookRules>()?
            .rules
            .iter()
            .any(ArchivedOutlookRule::is_listed)),
        None => Ok(false),
    }
}

pub async fn sidecar_forwards_to(
    server: &Server,
    account_id: u32,
    principal_id: u32,
) -> trc::Result<bool> {
    match stored_sidecar(server, account_id).await? {
        Some(stored) => Ok(stored
            .unarchive::<OutlookRules>()?
            .forwards_to(principal_id)),
        None => Ok(false),
    }
}

async fn stored_sidecar(
    server: &Server,
    account_id: u32,
) -> trc::Result<Option<Archive<ArchiveBytes>>> {
    server
        .store()
        .get_value::<Archive<ArchiveBytes>>(account_key(account_id, ExchangeClass::Rules))
        .await
        .caused_by(trc::location!())
}

pub fn queue_changes(batch: &mut BatchBuilder, account_id: u32, changes: Vec<SidecarChange>) {
    if changes.is_empty() {
        return;
    }
    batch
        .with_account_id(account_id)
        .with_collection(Collection::Principal)
        .with_document(0)
        .merge_fnc(ExchangeClass::Rules, move |_, bytes| {
            let mut stored = match bytes {
                Some(bytes) => <Archive<ArchiveBytes> as Deserialize>::deserialize(bytes)?
                    .deserialize::<OutlookRules>()?,
                None => OutlookRules::default(),
            };
            if !stored.apply(&changes) {
                Ok(MergeResult::Skip)
            } else if stored.rules.is_empty() && stored.next_stored == 0 {
                Ok(MergeResult::Delete)
            } else {
                Archiver::new(stored).serialize().map(MergeResult::Update)
            }
        });
}

#[cfg(all(test, stalwart_tests))]
#[rustfmt::skip]
#[path = "../../../../../stalwart-tests/unit/exchange/src/rules/sidecar/tests.rs"]
mod tests;
