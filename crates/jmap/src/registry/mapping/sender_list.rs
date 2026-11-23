/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::mail_rule::{
    Outcome, ServerSetProperties, patch_object, rule_error, save_changes, validate_object,
};
use crate::{
    api::query::QueryResponseBuilder,
    registry::{
        mapping::{RegistryGetResponse, RegistryQueryResponse, RegistrySetResponse},
        query::RegistryQueryFilters,
    },
};
use compact_str::format_compact;
use email::sieve::rules::{RuleError, SenderListKind, managed::ManagedSieveScript};
use jmap_proto::{error::set::SetError, types::state::State};
use jmap_tools::JsonPointer;
use registry::{
    jmap::{IntoValue, JmapValue, RegistryJsonPatch},
    schema::{
        prelude::Property,
        structs::{BlockedSender, SafeSender},
    },
    types::ObjectImpl,
};
use store::registry::RegistryFilterOp;
use types::id::Id;

pub(crate) async fn sender_list_get(
    mut get: RegistryGetResponse<'_>,
    kind: SenderListKind,
) -> trc::Result<RegistryGetResponse<'_>> {
    let script = get.server.managed_script_read(get.account_id).await?;
    let mut ids = get.ids.take();
    if let Some(ids) = &mut ids {
        ids.sort_unstable();
        ids.dedup();
    }

    for entry in script.into_senders(kind) {
        let id = Id::from(entry.id);
        if let Some(ids) = &mut ids {
            let Ok(idx) = ids.binary_search(&id) else {
                continue;
            };
            ids.remove(idx);
        }
        let address = entry.entry;
        get.insert(
            id,
            match kind {
                SenderListKind::Blocked => BlockedSender { address }.into_value(),
                SenderListKind::Safe => SafeSender { address }.into_value(),
            },
        );
    }

    for id in ids.into_iter().flatten() {
        get.not_found(id);
    }

    Ok(get)
}

pub(crate) async fn sender_list_set(
    mut set: RegistrySetResponse<'_>,
    kind: SenderListKind,
) -> trc::Result<RegistrySetResponse<'_>> {
    set.fail_all_update("Entries cannot be changed, remove the entry and add a new one.");
    let create = std::mem::take(&mut set.create);
    let destroy = std::mem::take(&mut set.destroy);

    let mut state = set.server.managed_script_load(set.account_id).await?;
    let list = state.script.senders_mut(kind);
    let mut outcomes = Vec::with_capacity(create.len() + destroy.len());
    let mut changed = false;

    for id in destroy {
        outcomes.push(match list.remove(id.id()) {
            Some(_) => {
                changed = true;
                Outcome::Destroyed(id)
            }
            None => Outcome::NotDestroyed(id, SetError::not_found()),
        });
    }

    for (client_id, value) in create {
        outcomes.push(
            match parse_address(kind, value)
                .and_then(|address| list.insert(&address).map_err(entry_error))
            {
                Ok(id) => {
                    changed = true;
                    Outcome::Created(client_id, Id::from(id), ServerSetProperties::new())
                }
                Err(err) => Outcome::NotCreated(client_id, err),
            },
        );
    }

    save_changes(set, state, outcomes, changed).await
}

pub(crate) async fn sender_list_query(
    mut query: RegistryQueryResponse<'_>,
    kind: SenderListKind,
) -> trc::Result<QueryResponseBuilder> {
    let mut needle = None;
    query.request.extract_filters(|property, op, value| {
        if property == Property::Address
            && op == RegistryFilterOp::Equal
            && needle.is_none()
            && let Some(value) = value.as_str()
        {
            needle = Some(value.trim().to_lowercase());
            true
        } else {
            false
        }
    })?;
    let has_sort = query
        .request
        .sort
        .as_ref()
        .is_some_and(|sort| !sort.is_empty());
    let params = query
        .request
        .extract_parameters(query.server.core.jmap.query_max_results, None)?;
    let (sort_by_id, is_ascending) = match params.sort_by {
        Property::Id if has_sort => (true, params.sort_ascending),
        Property::Id => (false, true),
        Property::Address => (false, params.sort_ascending),
        property => {
            return Err(trc::JmapEvent::UnsupportedSort
                .into_err()
                .details(format_compact!(
                    "Property {} is not supported for sorting",
                    property
                )));
        }
    };

    let script = query
        .server
        .managed_script_read(query.request.account_id.document_id())
        .await?;
    let mut matches = script
        .senders(kind)
        .iter()
        .filter(|entry| {
            needle
                .as_deref()
                .is_none_or(|needle| entry.entry.contains(needle))
        })
        .map(|entry| entry.id)
        .collect::<Vec<_>>();
    if sort_by_id {
        matches.sort_unstable();
    }
    if !is_ascending {
        matches.reverse();
    }

    let mut response = QueryResponseBuilder::new(
        matches.len(),
        query.server.core.jmap.query_max_results,
        State::Initial,
        &query.request,
    );
    for id in matches {
        if !response.add_id(Id::from(id)) {
            break;
        }
    }
    Ok(response)
}

fn parse_address(kind: SenderListKind, value: JmapValue<'_>) -> Result<String, SetError<Property>> {
    match kind {
        SenderListKind::Blocked => parse_entry::<BlockedSender>(value).map(|entry| entry.address),
        SenderListKind::Safe => parse_entry::<SafeSender>(value).map(|entry| entry.address),
    }
}

fn parse_entry<T: RegistryJsonPatch + ObjectImpl>(
    value: JmapValue<'_>,
) -> Result<T, SetError<Property>> {
    let mut entry = T::default();
    patch_object(&mut entry, &JsonPointer::new(vec![]), value, true)?;
    validate_object(&entry)?;
    Ok(entry)
}

fn entry_error(err: RuleError) -> SetError<Property> {
    match err {
        RuleError::EntryExists(id) => SetError::already_exists()
            .with_existing_id(Id::from(id))
            .with_description(err.to_string()),
        RuleError::TooManyEntries => SetError::over_quota().with_description(err.to_string()),
        err => rule_error(err).with_property(Property::Address),
    }
}
