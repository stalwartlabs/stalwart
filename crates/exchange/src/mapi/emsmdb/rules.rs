/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{
    access::LogonAccess,
    execute::{MailboxView, RopContext, RopError, RopResult},
    props::{PropBag, PropOut},
    state::{TableObject, mail_container},
    table::TableRow,
};
use crate::{
    folders::FolderNode,
    identity::principal_from_dn,
    mail::category::{AccountCategories, CategoryNames, CategoryUse},
    mapi::ids::MapiId,
    rules::{
        RulesWrite, has_rules, load_rule_set, load_rules, map::can_map, rule_addresses, save_rules,
    },
    store::{FolderKind, FolderRef, named::AccountNamedProps},
};
use email::{cache::mailbox::MailboxCacheAccess, mailbox::INBOX_ID};
use exchange_proto::{
    common::Utf16Le,
    ids::Eid,
    mapi::{
        ErrorCode,
        prop::{PropTag, PropValue, tags},
        rop::{DecodedRop, requests::ModifyRules},
        rule_logic::{
            DELEGATE_PROVIDER, EncodedRule, MappedAction, MappedDelegate, MappedPredicate,
            MappedRule, RuleFolder, RuleNames, RuleRecipient,
        },
    },
    rules::{
        Action, DelegateRecipient, DelegateRule, DeliverMode, MAX_VALUES, ManagedRule, MapiRule,
        Predicate, RuleBody, RuleId, RuleLogic, RuleSet, RuleState,
    },
};
use std::mem;
use trc::AddContext;
use types::special_use::SpecialUse;

pub const RULE_COLUMNS: [PropTag; 10] = [
    tags::RULE_ID,
    tags::RULE_SEQUENCE,
    tags::RULE_STATE,
    tags::RULE_USER_FLAGS,
    tags::RULE_CONDITION,
    tags::RULE_ACTIONS,
    tags::RULE_PROVIDER,
    tags::RULE_NAME,
    tags::RULE_LEVEL,
    tags::RULE_PROVIDER_DATA,
];

const RULE_ORGANIZER: &str = "RuleOrganizer";
const MAILBOX_RULES_PROVIDER: &str = "ExchangeMailboxRules14";
const UNMAPPED_PROVIDER: &str = "Stalwart Rules";
const MODIFY_RULES_REPLACE: u8 = 0x01;
const ROW_ADD: u8 = 0x01;
const ROW_MODIFY: u8 = 0x02;
const ROW_REMOVE: u8 = 0x04;
const MAX_RULES: usize = 256;
const MAX_WRITE_ATTEMPTS: usize = 3;

enum RuleEdit<'a> {
    Clear,
    Add(RuleProps<'a>),
    Modify(RuleId, RuleProps<'a>),
    Remove(RuleId),
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Mapping {
    Exact,
    StoredOnly,
}

#[derive(Default)]
struct RuleProps<'a> {
    sequence: Option<i32>,
    state: Option<u32>,
    user_flags: Option<u32>,
    level: Option<u32>,
    name: Option<String>,
    provider: Option<String>,
    provider_data: Option<&'a [u8]>,
    condition: Option<&'a [u8]>,
    actions: Option<&'a [u8]>,
}

pub fn is_rules_folder(folder_counter: u64) -> bool {
    mail_container(folder_counter) == Some(INBOX_ID)
}

fn rule_edits<'a>(request: &ModifyRules<'a>) -> Result<Vec<RuleEdit<'a>>, RopError> {
    let replace = match request.modify_rules_flags {
        0 => false,
        MODIFY_RULES_REPLACE => true,
        _ => return Err(RopError::Code(ErrorCode::INVALID_PARAM)),
    };
    let mut edits = Vec::with_capacity(request.rules_data.len().saturating_add(1));
    if replace {
        edits.push(RuleEdit::Clear);
    }
    for row in request.rules_data.iter() {
        let mut id = None;
        let mut props = RuleProps::default();
        for (tag, value) in row.values.iter() {
            match (tag, value) {
                (tags::RULE_ID, PropValue::I64(value)) => id = Some(RuleId(value.cast_unsigned())),
                (tags::RULE_SEQUENCE, PropValue::I32(value)) => props.sequence = Some(value),
                (tags::RULE_STATE, PropValue::I32(value)) => {
                    props.state = Some(value.cast_unsigned())
                }
                (tags::RULE_USER_FLAGS, PropValue::I32(value)) => {
                    props.user_flags = Some(value.cast_unsigned())
                }
                (tags::RULE_LEVEL, PropValue::I32(value)) => {
                    props.level = Some(value.cast_unsigned())
                }
                (tags::RULE_NAME, PropValue::Unicode(text)) => {
                    props.name = Some(utf16(&text));
                }
                (tags::RULE_PROVIDER, PropValue::Unicode(text)) => {
                    props.provider = Some(utf16(&text));
                }
                (tags::RULE_PROVIDER_DATA, PropValue::Binary(bytes)) => {
                    props.provider_data = Some(bytes)
                }
                (tags::RULE_CONDITION, PropValue::Restriction(bytes)) => {
                    props.condition = Some(bytes)
                }
                (tags::RULE_ACTIONS, PropValue::RuleAction(bytes)) => props.actions = Some(bytes),
                _ => {}
            }
        }
        edits.push(match (row.flags, replace, id) {
            (ROW_ADD, _, None)
                if props.condition.is_some()
                    && props.actions.is_some()
                    && props.provider.is_some() =>
            {
                RuleEdit::Add(props)
            }
            (ROW_MODIFY, false, Some(id)) => RuleEdit::Modify(id, props),
            (ROW_REMOVE, false, Some(id)) => RuleEdit::Remove(id),
            _ => return Err(RopError::Code(ErrorCode::INVALID_PARAM)),
        });
    }
    Ok(edits)
}

impl RuleProps<'_> {
    fn touches_mapi(&self) -> bool {
        self.remaps()
            || self.provider.is_some()
            || self.provider_data.is_some()
            || self.user_flags.is_some()
            || self.level.is_some()
    }

    fn remaps(&self) -> bool {
        self.condition.is_some() || self.actions.is_some()
    }

    fn update_rule(&self, rule: &mut ManagedRule) {
        if let Some(sequence) = self.sequence {
            rule.sequence = sequence;
        }
        if let Some(state) = self.state {
            rule.state = RuleState(state).stored();
        }
        if let Some(name) = &self.name {
            rule.name.clone_from(name);
        }
    }
}

fn utf16(text: &Utf16Le<'_>) -> String {
    let mut out = String::new();
    text.to_string_lossy(&mut out);
    out
}

impl RopContext<'_, '_> {
    pub async fn modify_rules(
        &mut self,
        rop: &DecodedRop<'_>,
        index: u8,
        request: &ModifyRules<'_>,
    ) -> RopResult {
        let folder = self.open_folder_at(self.input(rop.header.input_handle)?)?;
        let is_inbox = matches!(
            folder.node,
            FolderNode::Stored(FolderRef {
                kind: FolderKind::Mailbox,
                id: INBOX_ID,
            })
        );
        if !is_inbox {
            return Err(RopError::Code(ErrorCode::NOT_SUPPORTED));
        }
        let edits = rule_edits(request)?;
        let account_id = folder.mailbox_id;
        let server = self.request.server;
        let access_token = self.request.access_token;
        let mut scratch = EditScratch::default();
        let mut mapping = Mapping::Exact;
        for _ in 0..MAX_WRITE_ATTEMPTS {
            let mut loaded = load_rules(server, account_id).await?;
            let mut set = mem::take(&mut loaded.set);
            let before = set.rules.len();
            let mut carried = None;
            scratch.categories.clear();
            for edit in &edits {
                self.apply_rule_edit(
                    &mut set,
                    edit,
                    account_id,
                    &mut scratch,
                    mapping,
                    &mut carried,
                )
                .await?;
            }
            if let Some(rule) = carried.filter(is_hidden_delegate) {
                set.rules.push(rule);
            }
            if set.rules.len() > MAX_RULES.max(before) {
                return Err(RopError::Code(ErrorCode::NOT_ENOUGH_MEMORY));
            }
            set.sort();
            match save_rules(server, access_token, account_id, loaded, set).await? {
                RulesWrite::Written { .. } => {
                    if let Err(err) = scratch.categories.save(server, account_id).await {
                        trc::error!(err.caused_by(trc::location!()));
                    }
                    return self.respond_empty(rop, index);
                }
                RulesWrite::Conflict => {}
                RulesWrite::Forbidden => return Err(RopError::Code(ErrorCode::ACCESS_DENIED)),
                RulesWrite::Limit(_) | RulesWrite::RedirectLimit | RulesWrite::ScriptLimit(_) => {
                    return Err(RopError::Code(ErrorCode::NOT_ENOUGH_MEMORY));
                }
                RulesWrite::Invalid(reason) => {
                    trc::error!(
                        trc::StoreEvent::UnexpectedError
                            .into_err()
                            .account_id(account_id)
                            .ctx(trc::Key::Reason, reason)
                            .details("Outlook rule is not a valid mail rule")
                            .caused_by(trc::location!())
                    );
                    if mapping == Mapping::StoredOnly {
                        return Err(RopError::Code(ErrorCode::ERROR));
                    }
                    mapping = Mapping::StoredOnly;
                }
            }
        }
        Err(RopError::Code(ErrorCode::SERVER_BUSY))
    }

    async fn rules_view<'v>(
        &mut self,
        slot: &'v mut Option<MailboxView>,
        account_id: u32,
    ) -> trc::Result<&'v MailboxView> {
        let view = match slot.take() {
            Some(view) => view,
            None => self.mailbox(account_id).await?,
        };
        Ok(slot.insert(view))
    }

    async fn apply_rule_edit(
        &mut self,
        set: &mut RuleSet,
        edit: &RuleEdit<'_>,
        account_id: u32,
        scratch: &mut EditScratch,
        mapping: Mapping,
        carried: &mut Option<ManagedRule>,
    ) -> Result<(), RopError> {
        match edit {
            RuleEdit::Clear => {
                if let Some((position, _, _)) = set.delegate() {
                    *carried = set.remove(position);
                }
                while let Some(last) = set.rules.len().checked_sub(1) {
                    set.remove(last);
                }
            }
            RuleEdit::Remove(id) => {
                let position = set.position(*id).ok_or(ErrorCode::NOT_FOUND)?;
                set.remove(position);
            }
            RuleEdit::Add(props) => {
                let id = set.allocate_id().ok_or(ErrorCode::NOT_ENOUGH_MEMORY)?;
                let mapi = MapiRule {
                    provider: props.provider.as_deref().unwrap_or_default().into(),
                    provider_data: props.provider_data.unwrap_or_default().into(),
                    user_flags: props.user_flags.unwrap_or_default(),
                    level: props.level.unwrap_or_default(),
                    condition: props.condition.unwrap_or_default().into(),
                    actions: props.actions.unwrap_or_default().into(),
                };
                let body = match mapping {
                    Mapping::Exact if &*mapi.provider == DELEGATE_PROVIDER => {
                        if carried.is_none() {
                            *carried = take_hidden_delegate(set);
                        }
                        if set.delegate().is_some() {
                            RuleBody::StoredOnly
                        } else {
                            let body = self
                                .delegate_body(&mapi, account_id, carried_delegate(carried))
                                .await?;
                            if matches!(body, RuleBody::Delegate(_)) {
                                *carried = None;
                            }
                            body
                        }
                    }
                    Mapping::Exact => {
                        let view = self.rules_view(&mut scratch.view, account_id).await?;
                        self.mapped_body(&mapi, view, account_id, None, &mut scratch.categories)
                            .await?
                    }
                    Mapping::StoredOnly => RuleBody::StoredOnly,
                };
                set.rules.push(ManagedRule {
                    id,
                    sequence: props.sequence.unwrap_or_default(),
                    state: RuleState(props.state.unwrap_or_default()).stored(),
                    name: props.name.clone().unwrap_or_default(),
                    body,
                    mapi: Some(Box::new(mapi)),
                });
            }
            RuleEdit::Modify(id, props) => {
                let position = set.position(*id).ok_or(ErrorCode::NOT_FOUND)?;
                if mapping == Mapping::Exact
                    && carried.is_none()
                    && props.remaps()
                    && props.provider.as_deref() == Some(DELEGATE_PROVIDER)
                    && set.delegate().is_some_and(|(delegate, rule, _)| {
                        delegate != position && is_hidden_delegate(rule)
                    })
                {
                    *carried = take_hidden_delegate(set);
                }
                let position = set.position(*id).ok_or(ErrorCode::NOT_FOUND)?;
                let other_delegate = set
                    .delegate()
                    .is_some_and(|(delegate, _, _)| delegate != position);
                let rule = set.rules.get_mut(position).ok_or(ErrorCode::NOT_FOUND)?;
                if !props.touches_mapi() {
                    props.update_rule(rule);
                    return Ok(());
                }
                let mut mapi = match rule.mapi.take() {
                    Some(mapi) => mapi,
                    None => Box::new(
                        match generated_mapi(
                            rule,
                            self.rules_view(&mut scratch.view, account_id).await?,
                        ) {
                            Some(mapi) => mapi,
                            None if props.condition.is_some() && props.actions.is_some() => {
                                MapiRule {
                                    provider: RULE_ORGANIZER.into(),
                                    provider_data: Box::default(),
                                    user_flags: 0,
                                    level: 0,
                                    condition: Box::default(),
                                    actions: Box::default(),
                                }
                            }
                            None => return Err(RopError::Code(ErrorCode::NOT_SUPPORTED)),
                        },
                    ),
                };
                if let Some(provider) = &props.provider {
                    mapi.provider = provider.as_str().into();
                }
                if let Some(provider_data) = props.provider_data {
                    mapi.provider_data = provider_data.into();
                }
                if let Some(user_flags) = props.user_flags {
                    mapi.user_flags = user_flags;
                }
                if let Some(level) = props.level {
                    mapi.level = level;
                }
                if let Some(condition) = props.condition {
                    mapi.condition = condition.into();
                }
                if let Some(actions) = props.actions {
                    mapi.actions = actions.into();
                }
                if props.remaps() {
                    let previous = match mem::replace(&mut rule.body, RuleBody::StoredOnly) {
                        RuleBody::Delegate(delegate) => Some(delegate),
                        _ => None,
                    };
                    rule.body = match mapping {
                        Mapping::Exact
                            if other_delegate && &*mapi.provider == DELEGATE_PROVIDER =>
                        {
                            RuleBody::StoredOnly
                        }
                        Mapping::Exact => {
                            let view = self.rules_view(&mut scratch.view, account_id).await?;
                            self.mapped_body(
                                &mapi,
                                view,
                                account_id,
                                previous.as_ref().or(carried_delegate(carried)),
                                &mut scratch.categories,
                            )
                            .await?
                        }
                        Mapping::StoredOnly => RuleBody::StoredOnly,
                    };
                    if previous.is_none() && matches!(rule.body, RuleBody::Delegate(_)) {
                        *carried = None;
                    }
                }
                props.update_rule(rule);
                rule.mapi = Some(mapi);
            }
        }
        Ok(())
    }

    async fn mapped_body(
        &self,
        mapi: &MapiRule,
        view: &MailboxView,
        account_id: u32,
        previous: Option<&DelegateRule>,
        categories: &mut CategoryNames,
    ) -> trc::Result<RuleBody> {
        let recorded = categories.recorded();
        let body = self
            .decoded_body(mapi, view, account_id, previous, categories)
            .await?;
        if !matches!(body, RuleBody::Logic(_)) {
            categories.forget_since(recorded);
        }
        Ok(body)
    }

    async fn decoded_body(
        &self,
        mapi: &MapiRule,
        view: &MailboxView,
        account_id: u32,
        previous: Option<&DelegateRule>,
        categories: &mut CategoryNames,
    ) -> trc::Result<RuleBody> {
        if &*mapi.provider == DELEGATE_PROVIDER {
            return self.delegate_body(mapi, account_id, previous).await;
        }
        let names = RuleNames::resolve(&AccountNamedProps::new(&view.exchange));
        let Some(mapped) = MappedRule::decode(&mapi.condition, &mapi.actions, &names) else {
            return Ok(RuleBody::StoredOnly);
        };
        let mut actions = Vec::with_capacity(mapped.actions.len());
        for action in mapped.actions {
            actions.push(match action {
                MappedAction::Ready(action) => action,
                MappedAction::File { copy, folder_id } => {
                    let Some(mailbox_id) = mailbox_of_folder(view, folder_id) else {
                        return Ok(RuleBody::StoredOnly);
                    };
                    if copy {
                        Action::Copy { mailbox_id }
                    } else {
                        Action::Move { mailbox_id }
                    }
                }
                MappedAction::Redirect { kind, recipients } => {
                    let mut addresses = Vec::with_capacity(recipients.len());
                    for recipient in recipients {
                        match recipient {
                            RuleRecipient::Smtp(address) => addresses.push(address),
                            RuleRecipient::Directory(dn) => {
                                let Some(address) = self
                                    .directory_addresses(&dn)
                                    .await?
                                    .and_then(|addresses| addresses.into_iter().next())
                                else {
                                    return Ok(RuleBody::StoredOnly);
                                };
                                addresses.push(address);
                            }
                        }
                    }
                    Action::Redirect { kind, addresses }
                }
                MappedAction::AssignCategories(names) => {
                    match category_keywords(&names, CategoryUse::Assigned, categories) {
                        Some(keywords) => Action::AssignCategories(keywords),
                        None => return Ok(RuleBody::StoredOnly),
                    }
                }
            });
        }
        let (Some(conditions), Some(exceptions)) = (
            self.mapped_predicates(mapped.conditions, categories)
                .await?,
            self.mapped_predicates(mapped.exceptions, categories)
                .await?,
        ) else {
            return Ok(RuleBody::StoredOnly);
        };
        let logic = RuleLogic {
            conditions,
            exceptions,
            actions,
        };
        Ok(if logic.is_valid() && can_map(&logic) {
            RuleBody::Logic(logic)
        } else {
            RuleBody::StoredOnly
        })
    }

    async fn mapped_predicates(
        &self,
        mapped: Vec<MappedPredicate>,
        categories: &mut CategoryNames,
    ) -> trc::Result<Option<Vec<Predicate>>> {
        let mut predicates = Vec::with_capacity(mapped.len());
        for predicate in mapped {
            predicates.push(match predicate {
                MappedPredicate::Ready(predicate) => predicate,
                MappedPredicate::Address { field, recipients } => {
                    let mut values = Vec::with_capacity(recipients.len());
                    for recipient in recipients {
                        match recipient {
                            RuleRecipient::Smtp(address) => {
                                if !values.contains(&address) {
                                    values.push(address);
                                }
                            }
                            RuleRecipient::Directory(dn) => {
                                let Some(addresses) = self.directory_addresses(&dn).await? else {
                                    return Ok(None);
                                };
                                for address in addresses {
                                    if !values.contains(&address) {
                                        values.push(address);
                                    }
                                }
                            }
                        }
                        if values.len() > MAX_VALUES {
                            return Ok(None);
                        }
                    }
                    Predicate::Address { field, values }
                }
                MappedPredicate::Me(kind) => Predicate::Me(kind),
                MappedPredicate::Categories(names) => {
                    match category_keywords(&names, CategoryUse::Tested, categories) {
                        Some(keywords) => Predicate::Categories(keywords),
                        None => return Ok(None),
                    }
                }
            });
        }
        Ok(Some(predicates))
    }

    async fn directory_addresses(&self, dn: &str) -> trc::Result<Option<Vec<String>>> {
        let Some(account_id) = principal_from_dn(dn.as_bytes()) else {
            return Ok(None);
        };
        let server = self.request.server;
        let Some(account) = server
            .try_account(account_id)
            .await
            .caused_by(trc::location!())?
        else {
            return Ok(None);
        };
        // SPDX-SnippetBegin
        // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
        // SPDX-License-Identifier: LicenseRef-SEL
        #[cfg(feature = "enterprise")]
        if self
            .request
            .access_token
            .tenant_id()
            .is_some_and(|tenant_id| account.tenant_id() != Some(tenant_id))
        {
            return Ok(None);
        }
        // SPDX-SnippetEnd
        let addresses = rule_addresses(server, &account).await?;
        Ok((!addresses.is_empty()).then_some(addresses))
    }

    async fn delegate_body(
        &self,
        mapi: &MapiRule,
        account_id: u32,
        previous: Option<&DelegateRule>,
    ) -> trc::Result<RuleBody> {
        let Some(mapped) = MappedDelegate::decode(&mapi.actions)
            .filter(|mapped| mapped.recipients.len() <= MAX_VALUES)
        else {
            return Ok(RuleBody::StoredOnly);
        };
        let mode = match previous.map(|previous| previous.mode) {
            _ if mapped.deletes_own_copy => DeliverMode::DelegatesOnly,
            Some(DeliverMode::NoForward) if mapped.recipients.is_empty() => DeliverMode::NoForward,
            Some(
                mode @ (DeliverMode::DelegatesAndMe | DeliverMode::DelegatesAndSendInformationToMe),
            ) => mode,
            _ => DeliverMode::DelegatesAndMe,
        };
        let server = self.request.server;
        let mut recipients: Vec<DelegateRecipient> = Vec::with_capacity(mapped.recipients.len());
        for recipient in mapped.recipients {
            let principal_id = match &recipient {
                RuleRecipient::Directory(dn) => principal_from_dn(dn.as_bytes()),
                RuleRecipient::Smtp(address) => {
                    server.account_id_from_email(address, false).await?
                }
            };
            let Some(principal_id) = principal_id.filter(|id| *id != account_id) else {
                return Ok(RuleBody::StoredOnly);
            };
            if recipients
                .iter()
                .any(|known| known.principal_id == principal_id)
            {
                continue;
            }
            let address = match recipient {
                RuleRecipient::Smtp(address) => address,
                RuleRecipient::Directory(dn) => {
                    let Some(address) = self
                        .directory_addresses(&dn)
                        .await?
                        .and_then(|addresses| addresses.into_iter().next())
                    else {
                        return Ok(RuleBody::StoredOnly);
                    };
                    address
                }
            };
            recipients.push(DelegateRecipient {
                principal_id,
                address,
            });
        }
        let delegate = DelegateRule { mode, recipients };
        Ok(if delegate.is_valid() {
            RuleBody::Delegate(delegate)
        } else {
            RuleBody::StoredOnly
        })
    }

    pub(super) async fn rule_rows(
        &mut self,
        table: &TableObject,
    ) -> Result<Vec<TableRow>, RopError> {
        let account_id = table.folder.mailbox_id;
        if !is_rules_folder(table.folder.counter)
            || self.logon_access(account_id) != Some(LogonAccess::Owner)
        {
            return Ok(Vec::new());
        }
        let set = load_rule_set(self.request.server, account_id).await?;
        let mut view = None;
        let mut rows = Vec::with_capacity(set.rules.len());
        for rule in set.rules.iter().filter(|rule| !is_hidden_delegate(rule)) {
            let generated = match &rule.mapi {
                Some(_) => None,
                None => generated_mapi(rule, self.rules_view(&mut view, account_id).await?),
            };
            rows.push(rule_row(rule, rule.mapi.as_deref().or(generated.as_ref())));
        }
        Ok(rows)
    }

    pub(super) async fn has_rules(&mut self, account_id: u32) -> trc::Result<bool> {
        has_rules(self.request.server, account_id).await
    }
}

fn is_hidden_delegate(rule: &ManagedRule) -> bool {
    rule.mapi.is_none()
        && matches!(&rule.body, RuleBody::Delegate(delegate) if delegate.forwards().is_empty())
}

fn take_hidden_delegate(set: &mut RuleSet) -> Option<ManagedRule> {
    let position = set
        .delegate()
        .filter(|(_, rule, _)| is_hidden_delegate(rule))
        .map(|(position, _, _)| position)?;
    set.remove(position)
}

fn carried_delegate(carried: &Option<ManagedRule>) -> Option<&DelegateRule> {
    match &carried.as_ref()?.body {
        RuleBody::Delegate(delegate) => Some(delegate),
        _ => None,
    }
}

fn rule_row(rule: &ManagedRule, mapi: Option<&MapiRule>) -> TableRow {
    let mut bag = PropBag::with_capacity(mapi.map_or(0, |mapi| {
        mapi.condition
            .len()
            .saturating_add(mapi.actions.len())
            .saturating_add(mapi.provider_data.len())
    }));
    bag.push_i64(tags::RULE_ID, rule.id.0.cast_signed());
    bag.push_i32(tags::RULE_SEQUENCE, rule.sequence);
    bag.push_i32(tags::RULE_STATE, rule.state.0.cast_signed());
    bag.push_text(tags::RULE_NAME, &rule.name);
    match mapi {
        Some(mapi) => {
            bag.push_i32(tags::RULE_USER_FLAGS, mapi.user_flags.cast_signed());
            bag.push_i32(tags::RULE_LEVEL, mapi.level.cast_signed());
            bag.push_text(tags::RULE_PROVIDER, &mapi.provider);
            if mapi.provider_data.is_empty() {
                bag.push_error(tags::RULE_PROVIDER_DATA, ErrorCode::NOT_FOUND);
            } else {
                bag.push_binary(tags::RULE_PROVIDER_DATA, &mapi.provider_data);
            }
            bag.push_out(
                tags::RULE_CONDITION,
                &PropOut::Value(PropValue::Restriction(&mapi.condition)),
            );
            bag.push_out(
                tags::RULE_ACTIONS,
                &PropOut::Value(PropValue::RuleAction(&mapi.actions)),
            );
        }
        None => {
            bag.push_i32(tags::RULE_USER_FLAGS, 0);
            bag.push_i32(tags::RULE_LEVEL, 0);
            bag.push_text(tags::RULE_PROVIDER, UNMAPPED_PROVIDER);
            for tag in [
                tags::RULE_PROVIDER_DATA,
                tags::RULE_CONDITION,
                tags::RULE_ACTIONS,
            ] {
                bag.push_error(tag, ErrorCode::NOT_FOUND);
            }
        }
    }
    TableRow {
        key: rule.id.0,
        bag,
    }
}

fn generated_mapi(rule: &ManagedRule, view: &MailboxView) -> Option<MapiRule> {
    let (provider, encoded) = match &rule.body {
        RuleBody::Logic(logic) => {
            let names = RuleNames::resolve(&AccountNamedProps::new(&view.exchange));
            let categories = AccountCategories::new(&view.exchange);
            (
                logic_provider(logic),
                EncodedRule::encode(
                    logic,
                    &names,
                    |folder| folder_id_of(view, folder),
                    |keyword| categories.name(keyword),
                )?,
            )
        }
        RuleBody::Delegate(delegate) => (DELEGATE_PROVIDER, EncodedRule::delegate(delegate)?),
        RuleBody::StoredOnly => return None,
    };
    Some(MapiRule {
        provider: provider.into(),
        provider_data: Box::default(),
        user_flags: 0,
        level: 0,
        condition: encoded.condition.into(),
        actions: encoded.actions.into(),
    })
}

fn logic_provider(logic: &RuleLogic) -> &'static str {
    if logic.actions.iter().any(|action| {
        matches!(
            action,
            Action::MarkAsRead | Action::SetImportance(_) | Action::AssignCategories(_)
        )
    }) {
        MAILBOX_RULES_PROVIDER
    } else {
        RULE_ORGANIZER
    }
}

fn category_keywords(
    names: &[String],
    usage: CategoryUse,
    categories: &mut CategoryNames,
) -> Option<Vec<String>> {
    names
        .iter()
        .map(|name| categories.keyword(name, usage))
        .collect()
}

#[derive(Default)]
struct EditScratch {
    view: Option<MailboxView>,
    categories: CategoryNames,
}

fn folder_id_of(view: &MailboxView, folder: RuleFolder) -> Option<u64> {
    let mailbox_id = match folder {
        RuleFolder::Mailbox(mailbox_id) => mailbox_id,
        RuleFolder::Trash => {
            view.messages
                .as_deref()?
                .mailbox_by_role(&SpecialUse::Trash)?
                .document_id
        }
    };
    let node = FolderNode::Stored(FolderRef {
        kind: FolderKind::Mailbox,
        id: mailbox_id,
    });
    Some(
        MapiId::from_folder(&view.exchange, node)
            .to_eid()
            .to_le_u64(),
    )
}

fn mailbox_of_folder(view: &MailboxView, folder_id: u64) -> Option<u32> {
    let node = MapiId::from_eid(Eid::from_le_u64(folder_id))?.to_folder(&view.exchange)?;
    let FolderNode::Stored(FolderRef {
        kind: FolderKind::Mailbox,
        id,
    }) = node
    else {
        return None;
    };
    view.messages.as_deref()?.mailbox_by_id(&id).map(|_| id)
}

#[cfg(all(test, stalwart_tests))]
#[rustfmt::skip]
#[path = "../../../../../../stalwart-tests/unit/exchange/src/mapi/emsmdb/rules/tests.rs"]
mod tests;
