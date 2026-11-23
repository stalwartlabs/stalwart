/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

pub mod map;
pub mod sidecar;

use common::{
    Server,
    auth::{AccessToken, AccountCache},
};
use email::sieve::rules::{
    ManagedRule as CoreRule, ManagedScript, RuleError, active_redirects, is_same_addresses,
    is_same_redirects,
    managed::{ManagedScriptState, ManagedSieveScript, SaveError},
};
use exchange_proto::rules::{
    Action, DelegateRecipient, DelegateRule, ManagedRule, RedirectKind, RuleBody, RuleId,
    RuleLogic, RuleSet, RuleState, STORED_ID_BASE, is_valid_address,
};
use map::{
    delegate_mail_rule, mail_rule, rule_hash, rule_logic, rule_sequence, rule_state, with_header,
};
use registry::{
    schema::{
        enums::{MailRuleAddressOperator, Permission},
        structs::{MailRule, MailRuleCondition},
    },
    types::{ObjectImpl, error::ValidationError, list::List},
};
use sidecar::{
    OutlookRule, OutlookRules, RuleLink, SidecarChange, StoredDeliverMode, StoredMapi,
    StoredRecipient, StoredRedirect, queue_changes, read_sidecar, sidecar_has_rules,
};
use std::mem;
use store::write::BatchBuilder;
use trc::AddContext;

const UNNAMED_RULE: &str = "Outlook rule";
const FORWARD_PERMISSIONS: [Permission; 3] = [
    Permission::JmapSieveScriptCreate,
    Permission::JmapSieveScriptUpdate,
    Permission::SievePutScript,
];

pub struct LoadedRules {
    pub set: RuleSet,
    pub is_active: bool,
    state: ManagedScriptState,
    sidecar: OutlookRules,
    first_free: u64,
    dropped: Vec<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RulesWrite {
    Written { active: bool },
    Conflict,
    Limit(ValidationError),
    RedirectLimit,
    Forbidden,
    ScriptLimit(String),
    Invalid(String),
}

#[derive(Default)]
struct CoreEdits {
    created: bool,
    updated: bool,
    destroyed: bool,
    forwards: bool,
}

pub async fn load_rules(server: &Server, account_id: u32) -> trc::Result<LoadedRules> {
    let state = server
        .managed_script_load(account_id)
        .await
        .caused_by(trc::location!())?;
    let sidecar = read_sidecar(server, account_id).await?;
    let first_free = state.script.next_id();
    let mut set = RuleSet {
        next_id: first_free,
        rules: Vec::with_capacity(sidecar.rules.len()),
    };
    let mut dropped = Vec::new();
    for entry in &sidecar.rules {
        match view_rule(&state.script, entry) {
            Some(rule) => set.rules.push(rule),
            None => dropped.push(entry.id),
        }
    }
    set.sort();
    Ok(LoadedRules {
        set,
        is_active: state.is_active(),
        state,
        sidecar,
        first_free,
        dropped,
    })
}

pub async fn load_rule_set(server: &Server, account_id: u32) -> trc::Result<RuleSet> {
    load_rules(server, account_id)
        .await
        .map(|loaded| loaded.set)
}

pub async fn has_rules(server: &Server, account_id: u32) -> trc::Result<bool> {
    sidecar_has_rules(server, account_id).await
}

fn view_rule(script: &ManagedScript, entry: &OutlookRule) -> Option<ManagedRule> {
    let core = script.rule(entry.id).map(|core| &core.rule);
    if let Some(expected) = entry.pending
        && core.is_none_or(|core| rule_hash(core) != expected)
    {
        return None;
    }
    let mut rule = ManagedRule {
        id: RuleId(entry.id),
        sequence: entry.sequence,
        state: RuleState(entry.state),
        name: entry.name.clone(),
        body: RuleBody::StoredOnly,
        mapi: entry.mapi(),
    };
    match &entry.link {
        RuleLink::Core {
            hash,
            redirects,
            reply_template,
        } => {
            let core = core?;
            rule.body = RuleBody::Logic(rule_logic(core, redirects, reply_template.as_deref())?);
            rule.sequence = rule_sequence(core);
            if rule_hash(core) == *hash {
                rule.state = rule.state.with_enabled(core.is_enabled);
            } else {
                rule.state = rule_state(core, entry.state);
                rule.name.clone_from(&core.name);
                rule.mapi = None;
            }
        }
        RuleLink::StoredOnly => {}
        RuleLink::Delegate {
            has_core,
            mode,
            recipients,
        } => {
            if let (true, Some(core)) = (has_core, core) {
                rule.sequence = rule_sequence(core);
            }
            rule.body = RuleBody::Delegate(DelegateRule {
                mode: mode.mode(),
                recipients: recipients
                    .iter()
                    .map(|recipient| DelegateRecipient {
                        principal_id: recipient.principal_id,
                        address: recipient.address.clone(),
                    })
                    .collect(),
            });
        }
    }
    Some(rule)
}

pub async fn save_rules(
    server: &Server,
    access_token: &AccessToken,
    account_id: u32,
    loaded: LoadedRules,
    set: RuleSet,
) -> trc::Result<RulesWrite> {
    let LoadedRules {
        mut state,
        sidecar,
        first_free,
        dropped,
        ..
    } = loaded;
    let max_redirects = max_redirects(server);
    let mut next_core = set.next_id.max(state.script.next_id());
    let mut edits = CoreEdits::default();
    let mut pending = Vec::new();
    let mut changes = Vec::with_capacity(set.rules.len().saturating_add(dropped.len()));
    let mut kept = Vec::with_capacity(set.rules.len());

    for rule in &set.rules {
        let id = rule.id.0;
        let core = match &rule.body {
            RuleBody::Logic(logic)
                if logic.actions.is_empty() && !rule.state.has(RuleState::EXIT_LEVEL) =>
            {
                None
            }
            RuleBody::Logic(logic) => Some(
                unedited_core(&state.script, &sidecar, rule, logic)
                    .unwrap_or_else(|| mail_rule(rule, logic)),
            ),
            RuleBody::Delegate(delegate) if !delegate.forwards().is_empty() => {
                Some(delegate_mail_rule(rule, delegate))
            }
            RuleBody::Delegate(_) | RuleBody::StoredOnly => None,
        };
        let entry = |id: u64, link: RuleLink, pending: Option<u64>| OutlookRule {
            id,
            sequence: rule.sequence,
            state: rule.state.stored().0,
            name: rule.name.clone(),
            link,
            mapi: rule.mapi.as_deref().map(StoredMapi::new),
            pending,
        };
        match core {
            Some(core) => {
                let id = if id >= STORED_ID_BASE {
                    let id = next_core;
                    next_core = next_core.saturating_add(1);
                    id
                } else {
                    id
                };
                let hash = match upsert(&mut state.script, id, core, max_redirects, &mut edits) {
                    Ok(hash) => hash,
                    Err(outcome) => return Ok(outcome),
                };
                let link = match &rule.body {
                    RuleBody::Delegate(delegate) => delegate_link(delegate, true),
                    _ => RuleLink::Core {
                        hash,
                        redirects: redirects(rule),
                        reply_template: reply_template(rule),
                    },
                };
                kept.push(id);
                if id >= first_free {
                    let confirmed = entry(id, link, None);
                    pending.push(SidecarChange::AddPending(OutlookRule {
                        pending: Some(hash),
                        ..confirmed.clone()
                    }));
                    changes.push(SidecarChange::Upsert(confirmed));
                } else {
                    changes.push(SidecarChange::Upsert(entry(id, link, None)));
                }
            }
            None => {
                if state.script.remove(id).is_ok() {
                    edits.destroyed = true;
                }
                let link = match &rule.body {
                    RuleBody::Delegate(delegate) => delegate_link(delegate, false),
                    _ => RuleLink::StoredOnly,
                };
                if id < first_free || id >= STORED_ID_BASE {
                    kept.push(id);
                    changes.push(SidecarChange::Upsert(entry(id, link, None)));
                } else {
                    changes.push(SidecarChange::AddStored(entry(id, link, None)));
                }
            }
        }
    }
    kept.sort_unstable();
    for entry in &sidecar.rules {
        if kept.binary_search(&entry.id).is_ok() {
            continue;
        }
        changes.push(SidecarChange::Remove(entry.id));
        let is_core = matches!(
            entry.link,
            RuleLink::Core { .. } | RuleLink::Delegate { has_core: true, .. }
        );
        if is_core
            && dropped.binary_search(&entry.id).is_err()
            && state.script.remove(entry.id).is_ok()
        {
            edits.destroyed = true;
        }
    }

    if !edits.allowed(access_token) {
        return Ok(RulesWrite::Forbidden);
    }
    let mut active = state.is_active();
    if edits.created || edits.updated || edits.destroyed {
        active = state.script.runs_anything();
        commit_changes(server, account_id, &sidecar, mem::take(&mut pending)).await?;
        match server
            .managed_script_save(access_token, account_id, state)
            .await
            .caused_by(trc::location!())?
        {
            Ok(_) => {}
            Err(SaveError::Conflict) => return Ok(RulesWrite::Conflict),
            Err(SaveError::Invalid(
                err @ (RuleError::Compile(_) | RuleError::TooManyInstructions { .. }),
            )) => return Ok(RulesWrite::ScriptLimit(err.to_string())),
            Err(SaveError::Invalid(err)) => return Ok(RulesWrite::Invalid(err.to_string())),
        }
    }
    pending.append(&mut changes);
    commit_changes(server, account_id, &sidecar, pending).await?;
    Ok(RulesWrite::Written { active })
}

async fn commit_changes(
    server: &Server,
    account_id: u32,
    sidecar: &OutlookRules,
    mut changes: Vec<SidecarChange>,
) -> trc::Result<()> {
    changes.retain(|change| match change {
        SidecarChange::Upsert(rule) | SidecarChange::AddPending(rule) => {
            sidecar.rule(rule.id) != Some(rule)
        }
        SidecarChange::AddStored(_) | SidecarChange::Remove(_) => true,
    });
    if !changes.is_empty() {
        let mut batch = BatchBuilder::new();
        queue_changes(&mut batch, account_id, changes);
        server
            .commit_batch(batch)
            .await
            .caused_by(trc::location!())?;
    }
    Ok(())
}

impl LoadedRules {
    pub fn check_delegate(
        &self,
        server: &Server,
        access_token: &AccessToken,
        next: Option<&DelegateRule>,
    ) -> Result<(), RulesWrite> {
        let forwards = next.filter(|rule| !rule.forwards().is_empty());
        let current = self
            .sidecar
            .rules
            .iter()
            .find_map(|entry| match entry.link {
                RuleLink::Delegate { has_core: true, .. }
                    if self.dropped.binary_search(&entry.id).is_err() =>
                {
                    self.state
                        .script
                        .rule(entry.id)
                        .map(|core| (entry, &core.rule))
                }
                _ => None,
            });
        let (changed, redirects_changed) = match (forwards, current) {
            (Some(next), Some((entry, core))) => view_rule(&self.state.script, entry)
                .and_then(|view| {
                    let mut managed = CoreRule {
                        id: entry.id,
                        rule: delegate_mail_rule(&view, next),
                    };
                    managed.canonicalize().ok()?;
                    Some((
                        managed.rule != *core,
                        !is_same_redirects(active_redirects(core), active_redirects(&managed.rule)),
                    ))
                })
                .unwrap_or((true, true)),
            (Some(_), None) => (true, true),
            (None, _) => (false, false),
        };
        if redirects_changed
            && forwards.is_some_and(|rule| rule.forwards().len() > max_redirects(server))
        {
            return Err(RulesWrite::RedirectLimit);
        }
        let edits = CoreEdits {
            created: changed && current.is_none(),
            updated: changed && current.is_some(),
            destroyed: forwards.is_none() && current.is_some(),
            forwards: redirects_changed,
        };
        if edits.allowed(access_token) {
            Ok(())
        } else {
            Err(RulesWrite::Forbidden)
        }
    }
}

fn unedited_core(
    script: &ManagedScript,
    sidecar: &OutlookRules,
    rule: &ManagedRule,
    logic: &RuleLogic,
) -> Option<MailRule> {
    let RuleLink::Core {
        redirects,
        reply_template,
        ..
    } = &sidecar.rule(rule.id.0)?.link
    else {
        return None;
    };
    let current = &script.rule(rule.id.0)?.rule;
    let view = rule_logic(current, redirects, reply_template.as_deref())?;
    (view == *logic || is_same_core(canonical_core(rule, &view)?, canonical_core(rule, logic)?))
        .then(|| with_header(current, rule))
}

fn canonical_core(rule: &ManagedRule, logic: &RuleLogic) -> Option<MailRule> {
    let mut managed = CoreRule {
        id: rule.id.0,
        rule: mail_rule(rule, logic),
    };
    managed.canonicalize().ok()?;
    Some(managed.rule)
}

fn is_same_core(mut left: MailRule, mut right: MailRule) -> bool {
    let (conditions, others) = (&left.conditions, &right.conditions);
    is_same_conditions(&conditions.match_all, &others.match_all)
        && is_same_conditions(&conditions.match_any, &others.match_any)
        && is_same_conditions(&conditions.match_none, &others.match_none)
        && is_same_redirects(
            left.actions.redirect.take().as_ref(),
            right.actions.redirect.take().as_ref(),
        )
        && left.actions == right.actions
}

fn is_same_conditions(left: &List<MailRuleCondition>, right: &List<MailRuleCondition>) -> bool {
    let covers = |outer: &List<MailRuleCondition>, inner: &List<MailRuleCondition>| {
        inner.iter().all(|condition| {
            outer
                .iter()
                .any(|other| is_same_condition(condition, other))
        })
    };
    covers(left, right) && covers(right, left)
}

fn is_same_condition(left: &MailRuleCondition, right: &MailRuleCondition) -> bool {
    match (left, right) {
        (MailRuleCondition::From(left), MailRuleCondition::From(right))
        | (MailRuleCondition::ToOrCc(left), MailRuleCondition::ToOrCc(right))
            if left.operator == MailRuleAddressOperator::Is
                && right.operator == MailRuleAddressOperator::Is =>
        {
            is_same_addresses(left.values.as_slice(), right.values.as_slice())
        }
        _ => left == right,
    }
}

fn max_redirects(server: &Server) -> usize {
    let runtime = &server.core.sieve.untrusted_runtime;
    runtime.max_redirects().min(runtime.max_out_messages())
}

fn upsert(
    script: &mut ManagedScript,
    id: u64,
    mut rule: MailRule,
    max_redirects: usize,
    edits: &mut CoreEdits,
) -> Result<u64, RulesWrite> {
    if rule.name.is_empty() {
        rule.name = UNNAMED_RULE.to_string();
    }
    let mut errors = Vec::new();
    if !rule.validate(&mut errors) {
        return Err(errors
            .into_iter()
            .next()
            .map_or(RulesWrite::Invalid(String::new()), RulesWrite::Limit));
    }
    let mut managed = CoreRule { id, rule };
    managed
        .canonicalize()
        .map_err(|err| RulesWrite::Invalid(err.to_string()))?;
    let hash = rule_hash(&managed.rule);
    match script.rule(id) {
        Some(current) if current.rule == managed.rule => {}
        current => {
            if current.is_none_or(|current| {
                !is_same_redirects(
                    active_redirects(&current.rule),
                    active_redirects(&managed.rule),
                )
            }) {
                let redirects = redirect_count(&managed.rule);
                if redirects > max_redirects {
                    return Err(RulesWrite::RedirectLimit);
                }
                edits.forwards |= redirects > 0;
            }
            if current.is_some() {
                edits.updated = true;
            } else {
                edits.created = true;
            }
            script
                .upsert(managed)
                .map_err(|err| RulesWrite::Invalid(err.to_string()))?;
        }
    }
    Ok(hash)
}

impl CoreEdits {
    fn allowed(&self, access_token: &AccessToken) -> bool {
        (!self.created || access_token.has_permission(Permission::SysMailRuleCreate))
            && (!self.updated || access_token.has_permission(Permission::SysMailRuleUpdate))
            && (!self.destroyed || access_token.has_permission(Permission::SysMailRuleDestroy))
            && (!self.forwards
                || FORWARD_PERMISSIONS
                    .into_iter()
                    .any(|permission| access_token.has_permission(permission)))
    }
}

fn redirect_count(rule: &MailRule) -> usize {
    active_redirects(rule).map_or(0, |redirect| redirect.addresses.len())
}

fn redirects(rule: &ManagedRule) -> Vec<StoredRedirect> {
    let RuleBody::Logic(logic) = &rule.body else {
        return Vec::new();
    };
    logic
        .actions
        .iter()
        .filter_map(|action| match action {
            Action::Redirect { kind, addresses } if *kind != RedirectKind::Forward => {
                Some((kind, addresses))
            }
            _ => None,
        })
        .flat_map(|(kind, addresses)| {
            addresses
                .iter()
                .map(|address| StoredRedirect::new(address, *kind))
        })
        .collect()
}

fn reply_template(rule: &ManagedRule) -> Option<String> {
    let RuleBody::Logic(logic) = &rule.body else {
        return None;
    };
    logic.actions.iter().find_map(|action| match action {
        Action::ServerReply(reply) => Some(reply.template.clone()),
        _ => None,
    })
}

fn delegate_link(delegate: &DelegateRule, has_core: bool) -> RuleLink {
    RuleLink::Delegate {
        has_core,
        mode: StoredDeliverMode::new(delegate.mode),
        recipients: delegate
            .recipients
            .iter()
            .map(|recipient| StoredRecipient {
                principal_id: recipient.principal_id,
                address: recipient.address.clone(),
            })
            .collect(),
    }
}

pub async fn rule_addresses(server: &Server, account: &AccountCache) -> trc::Result<Vec<String>> {
    let mut out: Vec<String> = Vec::with_capacity(account.addresses.len());
    for address in account.addresses.iter() {
        let Some(domain) = server
            .domain_by_id(address.domain_id)
            .await
            .caused_by(trc::location!())?
        else {
            continue;
        };
        for name in domain.names.iter() {
            let mut value = String::with_capacity(address.local_part.len() + name.len() + 1);
            value.push_str(&address.local_part);
            value.push('@');
            value.push_str(name);
            value.make_ascii_lowercase();
            if is_valid_address(&value) && !out.contains(&value) {
                out.push(value);
            }
        }
    }
    Ok(out)
}

#[cfg(all(test, stalwart_tests))]
#[rustfmt::skip]
#[path = "../../../../../stalwart-tests/unit/exchange/src/rules/tests.rs"]
mod tests;
