/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{
    BUSY, NO_PERMISSION, NO_SCOPE, REDIRECT_LIMIT, RULE_FAILED,
    folders::{DelegateFolders, Target},
};
use crate::{
    ews::context::EwsCaller,
    folders::rights::{DelegateRole, GrantedRole},
    identity::primary_address,
    rules::{LoadedRules, RulesWrite, load_rules, map::DELEGATE_RULE_NAME, save_rules},
};
use common::Server;
use exchange_proto::{
    ews::{Operation, schema::ResponseCode, types::folder::UserId},
    rules::{
        DelegateRecipient, DelegateRule, DeliverMode, ManagedRule, RuleBody, RuleSet, RuleState,
    },
};
use std::{borrow::Cow, mem};
use trc::AddContext;

const MAX_WRITE_ATTEMPTS: usize = 3;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum DelegateEdit {
    Add,
    Update,
    Remove,
}

#[derive(Clone, Copy)]
pub(super) struct DelegateWriter<'a> {
    pub server: &'a Server,
    pub caller: EwsCaller<'a>,
    pub account_id: u32,
    pub sieve_scope: bool,
}

#[derive(Clone)]
pub(crate) struct Principal {
    pub id: u32,
    pub address: String,
    pub name: String,
}

pub(super) struct Planned {
    pub principal: Principal,
    pub levels: [Option<DelegateRole>; Target::COUNT],
    pub copies: Option<bool>,
    pub failed: bool,
    pub receives: bool,
}

pub(super) enum Resolved {
    User(Principal),
    Orphan(Principal),
}

pub(super) enum RuleOutcome {
    Saved { active: bool },
    Failed(ResponseCode, &'static str),
}

impl DelegateEdit {
    pub(super) const fn operation(self) -> Operation {
        match self {
            DelegateEdit::Add => Operation::AddDelegate,
            DelegateEdit::Update => Operation::UpdateDelegate,
            DelegateEdit::Remove => Operation::RemoveDelegate,
        }
    }
}

impl Resolved {
    pub(super) fn into_principal(self) -> Principal {
        match self {
            Resolved::User(principal) | Resolved::Orphan(principal) => principal,
        }
    }
}

impl Principal {
    pub(crate) async fn load_user(server: &Server, id: u32) -> trc::Result<Option<Self>> {
        let Some(account) = server
            .try_account(id)
            .await?
            .filter(|account| !account.is_group_account())
        else {
            return Ok(None);
        };
        let address = primary_address(server, &account)
            .await
            .caused_by(trc::location!())?
            .unwrap_or_default();
        let name = account
            .description
            .as_deref()
            .unwrap_or(&account.name)
            .to_string();
        Ok(Some(Principal { id, address, name }))
    }

    pub(super) fn orphan(recipient: &DelegateRecipient) -> Self {
        Principal {
            id: recipient.principal_id,
            address: recipient.address.clone(),
            name: recipient.address.clone(),
        }
    }

    pub(super) fn user_id(&self) -> UserId<'static> {
        UserId {
            primary_smtp_address: Some(Cow::Owned(self.address.clone())),
            display_name: Some(Cow::Owned(self.name.clone())),
            ..Default::default()
        }
    }
}

pub(super) async fn resolve(
    server: &Server,
    user_id: &UserId<'_>,
    rule: Option<&DelegateRule>,
) -> trc::Result<Option<Resolved>> {
    let Some(address) = user_id
        .primary_smtp_address
        .as_deref()
        .map(str::trim)
        .filter(|address| !address.is_empty())
    else {
        return Ok(None);
    };
    if let Some(recipient) = rule.and_then(|rule| {
        rule.recipients
            .iter()
            .find(|recipient| recipient.address.eq_ignore_ascii_case(address))
    }) {
        return Ok(Some(
            match Principal::load_user(server, recipient.principal_id).await? {
                Some(principal) => Resolved::User(principal),
                None => Resolved::Orphan(Principal::orphan(recipient)),
            },
        ));
    }
    Ok(match server.account_id_from_email(address, false).await? {
        Some(id) => Principal::load_user(server, id).await?.map(Resolved::User),
        None => None,
    })
}

async fn refreshed(
    server: &Server,
    rule: Option<&DelegateRule>,
) -> trc::Result<Option<DelegateRule>> {
    let Some(rule) = rule else {
        return Ok(None);
    };
    let mut recipients = Vec::with_capacity(rule.recipients.len());
    for recipient in &rule.recipients {
        if let Some(principal) = Principal::load_user(server, recipient.principal_id)
            .await?
            .filter(|principal| !principal.address.is_empty())
        {
            recipients.push(DelegateRecipient {
                principal_id: recipient.principal_id,
                address: principal.address,
            });
        }
    }
    Ok(Some(DelegateRule {
        mode: rule.mode,
        recipients,
    }))
}

impl Planned {
    pub(super) fn grants_anything(
        &self,
        folders: &DelegateFolders,
        current: Option<&DelegateRule>,
    ) -> bool {
        let granted = self.levels.iter().enumerate().any(|(index, level)| {
            folders.is_mapped(index)
                && match level {
                    Some(role) => *role != DelegateRole::None,
                    None => folders
                        .role(index, self.principal.id)
                        .is_some_and(|role| role != GrantedRole::Role(DelegateRole::None)),
                }
        });
        granted
            || self.copies.unwrap_or_else(|| {
                current.is_some_and(|rule| rule.has_recipient(self.principal.id))
            })
    }
}

pub(super) async fn apply(
    writer: DelegateWriter<'_>,
    folders: &DelegateFolders,
    loaded: LoadedRules,
    edit: DelegateEdit,
    planned: &mut [Planned],
    mode: Option<DeliverMode>,
) -> trc::Result<RuleOutcome> {
    let server = writer.server;
    let original = loaded.set.delegate().map(|(_, _, delegate)| delegate);
    let current = match original {
        Some(rule) if !writer.sieve_scope => Some(rule.clone()),
        _ => refreshed(server, original).await?,
    };
    let mut next = if writer.sieve_scope {
        let next = next_rule(current.clone(), mode, edit, planned);
        mark_receives(planned, next.as_ref());
        next
    } else {
        for plan in planned.iter_mut() {
            plan.copies = plan.copies.filter(|copies| *copies);
        }
        match edit {
            DelegateEdit::Remove => effective(current.as_ref()).cloned(),
            DelegateEdit::Add | DelegateEdit::Update => next_rule(
                current.clone(),
                mode.filter(|mode| *mode != DeliverMode::default()),
                edit,
                planned,
            ),
        }
    };
    let mut changed = effective(original) != next.as_ref();
    if changed {
        if !writer.sieve_scope {
            return Ok(RuleOutcome::Failed(
                ResponseCode::ErrorAccessDenied,
                NO_SCOPE,
            ));
        }
        if next.as_ref().is_some_and(|rule| !rule.is_valid()) {
            return Ok(RuleOutcome::Failed(
                ResponseCode::ErrorDelegateValidationFailed,
                RULE_FAILED,
            ));
        }
        if let Err(refused) =
            loaded.check_delegate(server, writer.caller.access_token, next.as_ref())
        {
            return Ok(refusal(refused, writer.account_id));
        }
    }
    let unchanged = RuleOutcome::Saved {
        active: loaded.is_active,
    };
    if edit == DelegateEdit::Remove {
        let outcome = if changed {
            write_rule(writer, loaded, next, mode, edit, planned).await?
        } else {
            unchanged
        };
        if matches!(outcome, RuleOutcome::Failed(..)) {
            return Ok(outcome);
        }
        folders.write(writer, edit, planned).await?;
        Ok(outcome)
    } else {
        folders.write(writer, edit, planned).await?;
        if changed && planned.iter().any(|plan| plan.failed) {
            next = next_rule(current, mode, edit, planned);
            mark_receives(planned, next.as_ref());
            changed = effective(original) != next.as_ref();
        }
        if changed {
            write_rule(writer, loaded, next, mode, edit, planned).await
        } else {
            Ok(unchanged)
        }
    }
}

async fn write_rule(
    writer: DelegateWriter<'_>,
    loaded: LoadedRules,
    next: Option<DelegateRule>,
    mode: Option<DeliverMode>,
    edit: DelegateEdit,
    planned: &[Planned],
) -> trc::Result<RuleOutcome> {
    let DelegateWriter {
        server,
        caller,
        account_id,
        ..
    } = writer;
    let mut first = Some((loaded, next));
    for _ in 0..MAX_WRITE_ATTEMPTS {
        let (mut loaded, next) = match first.take() {
            Some(first) => first,
            None => {
                let loaded = load_rules(server, account_id).await?;
                let current = refreshed(
                    server,
                    loaded.set.delegate().map(|(_, _, delegate)| delegate),
                )
                .await?;
                let next = next_rule(current, mode, edit, planned);
                (loaded, next)
            }
        };
        let mut set = mem::take(&mut loaded.set);
        if !place(&mut set, next) {
            return Ok(RuleOutcome::Failed(
                ResponseCode::ErrorDelegateValidationFailed,
                RULE_FAILED,
            ));
        }
        match save_rules(server, caller.access_token, account_id, loaded, set).await? {
            RulesWrite::Written { active } => return Ok(RuleOutcome::Saved { active }),
            RulesWrite::Conflict => {}
            refused => return Ok(refusal(refused, account_id)),
        }
    }
    Ok(RuleOutcome::Failed(ResponseCode::ErrorServerBusy, BUSY))
}

fn refusal(write: RulesWrite, account_id: u32) -> RuleOutcome {
    match write {
        RulesWrite::Forbidden => {
            RuleOutcome::Failed(ResponseCode::ErrorAccessDenied, NO_PERMISSION)
        }
        RulesWrite::RedirectLimit => {
            RuleOutcome::Failed(ResponseCode::ErrorDelegateValidationFailed, REDIRECT_LIMIT)
        }
        RulesWrite::Invalid(reason) => {
            trc::error!(
                trc::StoreEvent::UnexpectedError
                    .into_err()
                    .account_id(account_id)
                    .ctx(trc::Key::Reason, reason)
                    .details("Generated delegate rule does not compile")
                    .caused_by(trc::location!())
            );
            RuleOutcome::Failed(ResponseCode::ErrorDelegateValidationFailed, RULE_FAILED)
        }
        RulesWrite::Limit(_)
        | RulesWrite::ScriptLimit(_)
        | RulesWrite::Written { .. }
        | RulesWrite::Conflict => {
            RuleOutcome::Failed(ResponseCode::ErrorDelegateValidationFailed, RULE_FAILED)
        }
    }
}

fn next_rule(
    current: Option<DelegateRule>,
    mode: Option<DeliverMode>,
    edit: DelegateEdit,
    planned: &[Planned],
) -> Option<DelegateRule> {
    let mut rule = current.unwrap_or_else(|| DelegateRule {
        mode: DeliverMode::default(),
        recipients: Vec::new(),
    });
    if let Some(mode) = mode {
        rule.mode = mode;
    }
    for plan in planned.iter().filter(|plan| !plan.failed) {
        let principal_id = plan.principal.id;
        let copies = match edit {
            DelegateEdit::Remove => Some(false),
            DelegateEdit::Add | DelegateEdit::Update => plan.copies,
        };
        match copies {
            Some(true) => match rule
                .recipients
                .iter_mut()
                .find(|recipient| recipient.principal_id == principal_id)
            {
                Some(recipient) => plan.principal.address.clone_into(&mut recipient.address),
                None => rule.recipients.push(DelegateRecipient {
                    principal_id,
                    address: plan.principal.address.clone(),
                }),
            },
            Some(false) => rule
                .recipients
                .retain(|recipient| recipient.principal_id != principal_id),
            None => {}
        }
    }
    effective(Some(&rule)).is_some().then_some(rule)
}

fn mark_receives(planned: &mut [Planned], next: Option<&DelegateRule>) {
    for plan in planned {
        plan.receives = next.is_some_and(|rule| {
            !rule.forwards().is_empty() && rule.has_recipient(plan.principal.id)
        });
    }
}

fn effective(rule: Option<&DelegateRule>) -> Option<&DelegateRule> {
    rule.filter(|rule| rule.mode != DeliverMode::DelegatesOnly || !rule.recipients.is_empty())
}

fn place(set: &mut RuleSet, next: Option<DelegateRule>) -> bool {
    let position = set.delegate().map(|(position, _, _)| position);
    match (position, next) {
        (Some(position), Some(next)) => {
            let Some(rule) = set.rules.get_mut(position) else {
                return false;
            };
            rule.state = rule.state.with_enabled(!next.forwards().is_empty());
            rule.body = RuleBody::Delegate(next);
            rule.mapi = None;
        }
        (Some(position), None) => {
            set.remove(position);
        }
        (None, Some(next)) => {
            let Some(id) = set.allocate_id() else {
                return false;
            };
            let sequence = set
                .rules
                .first()
                .map_or(0, |rule| 0.min(rule.sequence.saturating_sub(1)));
            let state = RuleState(0).with_enabled(!next.forwards().is_empty());
            set.rules.insert(
                0,
                ManagedRule {
                    id,
                    sequence,
                    state,
                    name: DELEGATE_RULE_NAME.to_string(),
                    body: RuleBody::Delegate(next),
                    mapi: None,
                },
            );
        }
        (None, None) => {}
    }
    true
}
