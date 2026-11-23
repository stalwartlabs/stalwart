/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    api::query::QueryResponseBuilder,
    registry::{
        mapping::{RegistryGetResponse, RegistryQueryResponse, RegistrySetResponse},
        query::RegistryQueryFilters,
    },
};
use compact_str::format_compact;
use email::sieve::rules::{
    ManagedRule, ManagedScript, RuleError, active_redirects, canonical_keyword, is_same_redirects,
    managed::{ManagedScriptState, ManagedSieveScript, SaveError},
};
use jmap_proto::{
    error::set::{SetError, SetErrorType},
    types::state::State,
};
use jmap_tools::{JsonPointer, JsonPointerItem, Key, Map, Value};
use registry::{
    jmap::{
        IntoValue, JmapValue, JsonPointerPatch, MaybeUnpatched, RegistryJsonPatch, RegistryValue,
    },
    schema::{
        enums::{MailRuleAddressOperator, Permission},
        prelude::Property,
        structs::{MailRule, MailRuleCondition},
    },
    types::{ObjectImpl, list::List, map::Map as MemberSet},
};
use std::num::IntErrorKind;
use types::id::Id;
use utils::map::vec_map::VecMap;

#[derive(Clone, Copy)]
struct Forwarding {
    is_allowed: bool,
    max_addresses: usize,
}

pub(super) type ServerSetProperties = Map<'static, Property, RegistryValue>;
type Patch<'x> = (JsonPointer<Property>, JmapValue<'x>);

pub(super) enum Outcome {
    Created(String, Id, ServerSetProperties),
    NotCreated(String, SetError<Property>),
    Updated(Id, ServerSetProperties),
    NotUpdated(Id, SetError<Property>),
    Destroyed(Id),
    NotDestroyed(Id, SetError<Property>),
}

pub(crate) async fn mail_rule_get(
    mut get: RegistryGetResponse<'_>,
) -> trc::Result<RegistryGetResponse<'_>> {
    let script = get.server.managed_script_read(get.account_id).await?;
    let mut ids = get.ids.take();
    if let Some(ids) = &mut ids {
        ids.sort_unstable();
        ids.dedup();
    }

    for ManagedRule { id, rule } in script.rules {
        let id = Id::from(id);
        if let Some(ids) = &mut ids {
            let Ok(idx) = ids.binary_search(&id) else {
                continue;
            };
            ids.remove(idx);
        }
        get.insert(id, rule.into_value());
    }

    for id in ids.into_iter().flatten() {
        get.not_found(id);
    }

    Ok(get)
}

pub(crate) async fn mail_rule_set(
    mut set: RegistrySetResponse<'_>,
) -> trc::Result<RegistrySetResponse<'_>> {
    let create = std::mem::take(&mut set.create);
    let update = std::mem::take(&mut set.update);
    let destroy = std::mem::take(&mut set.destroy);
    let can_forward = [
        Permission::JmapSieveScriptCreate,
        Permission::JmapSieveScriptUpdate,
        Permission::SievePutScript,
    ]
    .into_iter()
    .any(|permission| set.access_token.has_permission(permission));
    let runtime = &set.server.core.sieve.untrusted_runtime;
    let forwarding = Forwarding {
        is_allowed: can_forward,
        max_addresses: runtime.max_redirects().min(runtime.max_out_messages()),
    };

    let mut state = set.server.managed_script_load(set.account_id).await?;
    let mut outcomes = Vec::with_capacity(create.len() + update.len() + destroy.len());
    let changed = apply_changes(
        &mut state.script,
        create,
        update,
        destroy,
        forwarding,
        &mut outcomes,
    );
    save_changes(set, state, outcomes, changed).await
}

pub(super) async fn save_changes(
    set: RegistrySetResponse<'_>,
    state: ManagedScriptState,
    mut outcomes: Vec<Outcome>,
    changed: bool,
) -> trc::Result<RegistrySetResponse<'_>> {
    if !changed {
        return Ok(finish(set, outcomes, None));
    }
    match set
        .server
        .managed_script_save(set.access_token, set.account_id, state)
        .await?
    {
        Ok(change_id) => Ok(finish(set, outcomes, change_id)),
        Err(SaveError::Conflict) => {
            fail_applied(&mut outcomes, || {
                SetError::forbidden()
                    .with_description("Another process modified the mail rules, please try again.")
            });
            Ok(finish(set, outcomes, None))
        }
        Err(SaveError::Invalid(err)) => {
            let description = err.to_string();
            fail_applied(&mut outcomes, || invalid(description.clone()));
            Ok(finish(set, outcomes, None))
        }
    }
}

pub(super) fn fail_applied(outcomes: &mut [Outcome], error: impl Fn() -> SetError<Property>) {
    for outcome in outcomes {
        *outcome = match std::mem::replace(outcome, Outcome::Destroyed(Id::default())) {
            Outcome::Created(client_id, ..) => Outcome::NotCreated(client_id, error()),
            Outcome::Updated(id, _) => Outcome::NotUpdated(id, error()),
            Outcome::Destroyed(id) => Outcome::NotDestroyed(id, error()),
            failed => failed,
        };
    }
}

pub(crate) async fn mail_rule_query(
    mut query: RegistryQueryResponse<'_>,
) -> trc::Result<QueryResponseBuilder> {
    let account_id = query.request.account_id.document_id();
    query.request.extract_filters(|_, _, _| false)?;
    let params = query
        .request
        .extract_parameters(query.server.core.jmap.query_max_results, None)?;

    let mut matches = query
        .server
        .managed_script_read(account_id)
        .await?
        .rules
        .into_iter()
        .map(|rule| (rule.id, rule.rule.position))
        .collect::<Vec<_>>();
    match params.sort_by {
        Property::Id => matches.sort_unstable_by_key(|(id, _)| *id),
        Property::Position => matches.sort_unstable_by_key(|(id, position)| (*position, *id)),
        property => {
            return Err(trc::JmapEvent::UnsupportedSort
                .into_err()
                .details(format_compact!(
                    "Property {} is not supported for sorting",
                    property
                )));
        }
    }
    if !params.sort_ascending {
        matches.reverse();
    }

    let mut response = QueryResponseBuilder::new(
        matches.len(),
        query.server.core.jmap.query_max_results,
        State::Initial,
        &query.request,
    );
    for (id, _) in matches {
        if !response.add_id(Id::from(id)) {
            break;
        }
    }
    Ok(response)
}

fn apply_changes(
    script: &mut ManagedScript,
    create: VecMap<String, JmapValue<'_>>,
    update: Vec<(Id, JmapValue<'_>)>,
    destroy: Vec<Id>,
    forwarding: Forwarding,
    outcomes: &mut Vec<Outcome>,
) -> bool {
    let mut changed = false;

    for (client_id, value) in create {
        let mut rule = MailRule::default();
        let [omits_enabled, omits_position] =
            [Property::IsEnabled, Property::Position].map(|property| {
                value
                    .as_object()
                    .is_some_and(|object| !object.contains_key(&Key::Property(property)))
            });
        let sent_name = value
            .as_object()
            .and_then(|object| object.get(&Key::Property(Property::Name)))
            .cloned();
        let result = patch_object(&mut rule, &JsonPointer::new(vec![]), value, true)
            .and_then(|_| validate_rule(&rule, None, forwarding))
            .and_then(|_| {
                let id = script.next_id();
                script
                    .upsert(ManagedRule { id, rule })
                    .map_err(rule_error)?;
                let mut properties = ServerSetProperties::with_capacity(5);
                if let Some(ManagedRule { rule, .. }) = script.rule(id) {
                    if omits_enabled {
                        properties
                            .insert_unchecked(Property::IsEnabled, rule.is_enabled.into_value());
                    }
                    if omits_position {
                        properties.insert_unchecked(Property::Position, rule.position.into_value());
                    }
                    if sent_name.as_ref().and_then(Value::as_str).as_deref() != Some(&*rule.name) {
                        properties.insert_unchecked(Property::Name, rule.name.clone().into_value());
                    }
                    properties.insert_unchecked(
                        Property::Conditions,
                        rule.conditions.clone().into_value(),
                    );
                    properties
                        .insert_unchecked(Property::Actions, rule.actions.clone().into_value());
                }
                Ok((id, properties))
            });
        outcomes.push(match result {
            Ok((id, properties)) => {
                changed = true;
                Outcome::Created(client_id, Id::from(id), properties)
            }
            Err(err) => Outcome::NotCreated(client_id, err),
        });
    }

    for (id, value) in update {
        let Some(mut rule) = script.rule(id.id()).map(|rule| rule.rule.clone()) else {
            outcomes.push(Outcome::NotUpdated(id, SetError::not_found()));
            continue;
        };
        let result = value
            .into_expanded_object()
            .map(|(key, value)| {
                let mut ptr = match key {
                    Key::Property(prop) => {
                        JsonPointer::new(vec![JsonPointerItem::Key(Key::Property(prop))])
                    }
                    Key::Borrowed(other) => JsonPointer::parse(other),
                    Key::Owned(other) => JsonPointer::parse(&other),
                };
                normalize_indexes(&mut ptr).map(|_| (ptr, value))
            })
            .collect::<Result<Vec<_>, _>>()
            .and_then(|mut patches| {
                check_overlaps(&patches)?;
                patches.iter_mut().try_for_each(|(ptr, value)| {
                    match value {
                        Value::Object(_) => reset_replaced_object(&mut rule, ptr),
                        Value::Null | Value::Bool(false) => resolve_removed_member(&rule, ptr),
                        _ => {}
                    }
                    patch_object(&mut rule, ptr, value.clone(), false)
                })?;
                let current = script.rule(id.id()).map(|current| &current.rule);
                validate_rule(&rule, current, forwarding)?;
                let requested = rule.clone();
                script
                    .upsert(ManagedRule { id: id.id(), rule })
                    .map_err(rule_error)?;
                Ok(script
                    .rule(id.id())
                    .map(|stored| changed_properties(&requested, &stored.rule, &patches))
                    .unwrap_or_else(ServerSetProperties::new))
            });
        outcomes.push(match result {
            Ok(properties) => {
                changed = true;
                Outcome::Updated(id, properties)
            }
            Err(err) => Outcome::NotUpdated(id, err),
        });
    }

    for id in destroy {
        outcomes.push(match script.remove(id.id()) {
            Ok(_) => {
                changed = true;
                Outcome::Destroyed(id)
            }
            Err(_) => Outcome::NotDestroyed(id, SetError::not_found()),
        });
    }

    changed
}

fn check_overlaps(patches: &[Patch<'_>]) -> Result<(), SetError<Property>> {
    let mut paths = patches
        .iter()
        .map(|(ptr, _)| ptr.as_slice())
        .collect::<Vec<_>>();
    paths.sort_unstable();
    if paths
        .windows(2)
        .any(|pair| matches!(pair, [first, second] if second.starts_with(first)))
    {
        Err(SetError::invalid_patch()
            .with_description("A patch path is the prefix of another one."))
    } else {
        Ok(())
    }
}

fn normalize_indexes(ptr: &mut JsonPointer<Property>) -> Result<(), SetError<Property>> {
    if let [
        JsonPointerItem::Key(Key::Property(Property::Conditions)),
        _,
        index,
        rest @ ..,
    ] = ptr.as_mut_slice()
    {
        normalize_index(index)?;
        if let [
            JsonPointerItem::Key(Key::Property(Property::Slots)),
            slot,
            ..,
        ] = rest
        {
            normalize_index(slot)?;
        }
    }
    Ok(())
}

fn normalize_index(item: &mut JsonPointerItem<Property>) -> Result<(), SetError<Property>> {
    let index = match item {
        JsonPointerItem::Number(index) => u32::try_from(*index).ok(),
        _ => match item.as_string_key().map(str::parse::<u32>) {
            Some(Ok(index)) => Some(index),
            Some(Err(err)) if *err.kind() == IntErrorKind::PosOverflow => None,
            _ => return Ok(()),
        },
    };
    match index {
        Some(index) => {
            *item = JsonPointerItem::Number(u64::from(index));
            Ok(())
        }
        None => Err(SetError::invalid_patch().with_description("A list index is out of range.")),
    }
}

fn resolve_removed_member(rule: &MailRule, ptr: &mut JsonPointer<Property>) {
    let Some((member, path)) = ptr.as_mut_slice().split_last_mut() else {
        return;
    };
    let (members, spelling): (&MemberSet<String>, Spelling) = match path {
        [
            JsonPointerItem::Key(Key::Property(Property::Actions)),
            JsonPointerItem::Key(Key::Property(Property::AddKeywords)),
        ] => (&rule.actions.add_keywords, Spelling::Keyword),
        [
            JsonPointerItem::Key(Key::Property(Property::Actions)),
            JsonPointerItem::Key(Key::Property(Property::RemoveKeywords)),
        ] => (&rule.actions.remove_keywords, Spelling::Keyword),
        [
            JsonPointerItem::Key(Key::Property(Property::Conditions)),
            JsonPointerItem::Key(Key::Property(list)),
            JsonPointerItem::Number(index),
            JsonPointerItem::Key(Key::Property(property)),
        ] => match (condition_at(rule, *list, *index), property) {
            (Some(MailRuleCondition::Keyword(test)), Property::Keywords) => {
                (&test.keywords, Spelling::Keyword)
            }
            (
                Some(
                    MailRuleCondition::From(test)
                    | MailRuleCondition::To(test)
                    | MailRuleCondition::Cc(test)
                    | MailRuleCondition::ToOrCc(test)
                    | MailRuleCondition::RecipientAddress(test),
                ),
                Property::Values,
            ) if test.operator == MailRuleAddressOperator::Domain => {
                (&test.values, Spelling::Domain)
            }
            _ => return,
        },
        _ => return,
    };
    let Some(requested) = member.as_string_key() else {
        return;
    };
    if members.iter().any(|stored| stored == requested) {
        return;
    }
    if let Some(stored) = spelling.find(members, requested) {
        *member = JsonPointerItem::Key(Key::Owned(stored.clone()));
    }
}

fn condition_at(rule: &MailRule, list: Property, index: u64) -> Option<&MailRuleCondition> {
    let conditions: &List<MailRuleCondition> = match list {
        Property::MatchAll => &rule.conditions.match_all,
        Property::MatchAny => &rule.conditions.match_any,
        Property::MatchNone => &rule.conditions.match_none,
        _ => return None,
    };
    conditions.0.get(&u32::try_from(index).ok()?)
}

#[derive(Clone, Copy)]
enum Spelling {
    Keyword,
    Domain,
}

impl Spelling {
    fn find<'x>(self, members: &'x MemberSet<String>, requested: &str) -> Option<&'x String> {
        match self {
            Spelling::Keyword => {
                let requested =
                    canonical_keyword(requested.chars().filter(|ch| !ch.is_whitespace()).collect())
                        .ok()?;
                members.iter().find(|stored| **stored == requested)
            }
            Spelling::Domain => {
                let requested = requested.trim().trim_start_matches('@');
                members
                    .iter()
                    .find(|stored| stored.eq_ignore_ascii_case(requested))
            }
        }
    }
}

fn reset_replaced_object(rule: &mut MailRule, ptr: &JsonPointer<Property>) {
    match ptr.as_slice() {
        [JsonPointerItem::Key(Key::Property(Property::Conditions))] => {
            rule.conditions = Default::default();
        }
        [JsonPointerItem::Key(Key::Property(Property::Actions))] => {
            rule.actions = Default::default();
        }
        [
            JsonPointerItem::Key(Key::Property(Property::Actions)),
            JsonPointerItem::Key(Key::Property(property)),
        ] => match property {
            Property::Redirect => rule.actions.redirect = None,
            Property::Reply => rule.actions.reply = None,
            Property::Reject => rule.actions.reject = None,
            _ => {}
        },
        [
            JsonPointerItem::Key(Key::Property(Property::Conditions)),
            _,
            _,
            JsonPointerItem::Key(Key::Property(Property::Slots)),
            _,
        ] => {
            let _ = patch_object(rule, ptr, Value::Null, false);
        }
        _ => {}
    }
}

fn changed_properties(
    requested: &MailRule,
    stored: &MailRule,
    patches: &[Patch<'_>],
) -> ServerSetProperties {
    let mut properties = ServerSetProperties::new();
    insert_changed(
        &mut properties,
        Property::Name,
        &requested.name,
        &stored.name,
        patches,
    );
    insert_changed(
        &mut properties,
        Property::Conditions,
        &requested.conditions,
        &stored.conditions,
        patches,
    );
    insert_changed(
        &mut properties,
        Property::Actions,
        &requested.actions,
        &stored.actions,
        patches,
    );
    properties
}

fn insert_changed<T: Clone + PartialEq + IntoValue>(
    properties: &mut ServerSetProperties,
    property: Property,
    requested: &T,
    stored: &T,
    patches: &[Patch<'_>],
) {
    let mut sent = patches
        .iter()
        .filter_map(|(ptr, value)| match ptr.as_slice().split_first() {
            Some((JsonPointerItem::Key(Key::Property(key)), path)) if *key == property => {
                Some((path, value))
            }
            _ => None,
        })
        .peekable();
    let is_changed = requested != stored;
    if !is_changed && sent.peek().is_none() {
        return;
    }
    let stored = stored.clone().into_value();
    if is_changed || !sent.all(|(path, sent)| is_as_sent(value_at(&stored, path), sent)) {
        properties.insert_unchecked(property, stored);
    }
}

fn value_at<'v, 'x>(
    value: &'v JmapValue<'x>,
    path: &[JsonPointerItem<Property>],
) -> Option<&'v JmapValue<'x>> {
    path.iter().try_fold(value, |value, item| {
        let object = value.as_object()?;
        match item {
            JsonPointerItem::Key(key) => object.get(key),
            JsonPointerItem::Number(number) => object.get(&Key::Owned(number.to_string())),
            _ => None,
        }
    })
}

fn is_as_sent(stored: Option<&JmapValue<'_>>, sent: &JmapValue<'_>) -> bool {
    match (stored, sent) {
        (None, Value::Null | Value::Bool(false)) => true,
        (Some(Value::Object(stored)), Value::Object(sent)) => sent
            .iter()
            .all(|(key, value)| is_as_sent(stored.get(key), value)),
        (Some(stored), sent) => stored == sent,
        (None, _) => false,
    }
}

pub(super) fn finish(
    mut set: RegistrySetResponse<'_>,
    outcomes: Vec<Outcome>,
    change_id: Option<u64>,
) -> RegistrySetResponse<'_> {
    for outcome in outcomes {
        match outcome {
            Outcome::Created(client_id, id, properties) => {
                let mut created = Map::with_capacity(properties.len() + 1);
                created.insert_unchecked(Property::Id, Value::Element(RegistryValue::Id(id)));
                created.as_mut_vec().extend(properties.into_vec());
                set.response
                    .created
                    .insert(client_id, Value::Object(created));
            }
            Outcome::NotCreated(client_id, err) => set.response.not_created.append(client_id, err),
            Outcome::Updated(id, properties) => set.response.updated.append(
                id,
                (!properties.is_empty()).then_some(Value::Object(properties)),
            ),
            Outcome::NotUpdated(id, err) => set.response.not_updated.append(id, err),
            Outcome::Destroyed(id) => set.response.destroyed.push(id),
            Outcome::NotDestroyed(id, err) => set.response.not_destroyed.append(id, err),
        }
    }
    if let Some(change_id) = change_id {
        set.response.new_state = Some(State::Exact(change_id));
    }
    set
}

pub(super) fn patch_object(
    object: &mut impl RegistryJsonPatch,
    ptr: &JsonPointer<Property>,
    value: Value<'_, Property, RegistryValue>,
    is_create: bool,
) -> Result<(), SetError<Property>> {
    match object.patch(JsonPointerPatch::new(ptr).with_create(is_create), value) {
        Ok(MaybeUnpatched::Patched) => Ok(()),
        Ok(MaybeUnpatched::Unpatched { .. } | MaybeUnpatched::UnpatchedMany { .. }) => {
            Err(SetError::invalid_properties().with_description("Cannot set property."))
        }
        Err(err) => Err(err.into()),
    }
}

pub(super) fn validate_object(object: &impl ObjectImpl) -> Result<(), SetError<Property>> {
    let mut errors = Vec::new();
    if object.validate(&mut errors) {
        Ok(())
    } else {
        Err(SetError::new(SetErrorType::ValidationFailed).with_validation_errors(errors))
    }
}

fn validate_rule(
    rule: &MailRule,
    current: Option<&MailRule>,
    forwarding: Forwarding,
) -> Result<(), SetError<Property>> {
    validate_object(rule)?;
    let redirect = active_redirects(rule);
    let addresses = redirect.map_or(0, |redirect| redirect.addresses.len());
    if addresses == 0
        || current.is_some_and(|current| is_same_redirects(active_redirects(current), redirect))
    {
        Ok(())
    } else if !forwarding.is_allowed {
        Err(SetError::forbidden()
            .with_description("Forwarding rules require permission to write Sieve scripts."))
    } else if addresses > forwarding.max_addresses {
        Err(invalid(format!(
            "The rule forwards to {addresses} addresses, but the server forwards a message to at most {} (maxRedirects and maxOutMessages).",
            forwarding.max_addresses
        )))
    } else {
        Ok(())
    }
}

pub(super) fn rule_error(err: RuleError) -> SetError<Property> {
    invalid(err.to_string())
}

fn invalid(description: String) -> SetError<Property> {
    SetError::invalid_properties().with_description(description)
}

#[cfg(all(test, stalwart_tests))]
#[rustfmt::skip]
#[path = "../../../../../../stalwart-tests/unit/jmap/src/registry/mapping/mail_rule/tests.rs"]
mod tests;
