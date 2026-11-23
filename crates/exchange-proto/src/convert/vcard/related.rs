/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::{cmp::Ordering, convert::identity, mem};

use calcard::vcard::{
    VCard, VCardEntry, VCardParameter, VCardParameterName, VCardParameterValue, VCardProperty,
    VCardType, VCardValue, VCardValueType, VCardVersion,
};
use smallvec::{SmallVec, smallvec};

use super::{
    patch::uri_scheme,
    props::{ASSISTANT, CHILDRENS_NAMES, MANAGER_NAME, SPOUSE_NAME},
};
use crate::mapi::prop::PropId;

const APPLE_PROPERTY: &str = "X-ABRELATEDNAMES";
const LABEL_PROPERTY: &str = "X-ABLabel";
const ITEM_GROUP: &str = "item";
const MANAGER_TYPE: &str = "manager";
const ASSISTANT_TYPE: &str = "assistant";

macro_rules! relation_property {
    ($name:ident, [$($ty:tt)*], [$($wrap:tt)*] $(, $($rest:tt)*)?) => {
        hashify::map_ignore_case!($name.as_bytes(), $($ty)*,
            "X-MS-CHILD" => $($wrap)*(OtherName::Legacy(Relation::Child)),
            "X-CHILD" => $($wrap)*(OtherName::Legacy(Relation::Child)),
            "X-MS-SPOUSE" => $($wrap)*(OtherName::Legacy(Relation::Spouse)),
            "X-MS-MANAGER" => $($wrap)*(OtherName::Legacy(Relation::Manager)),
            "X-MS-ASSISTANT" => $($wrap)*(OtherName::Legacy(Relation::Assistant)),
            "X-ASSISTANT" => $($wrap)*(OtherName::Legacy(Relation::Assistant)),
            "X-ABRELATEDNAMES" => $($wrap)*(OtherName::Apple),
            $($($rest)*)?
        )
    };
}

pub(super) use relation_property;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(super) enum Relation {
    Child,
    Spouse,
    Manager,
    Assistant,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(super) enum Form {
    Related,
    Apple,
    Partner,
    Legacy,
}

#[derive(Clone, Copy)]
pub(super) enum OtherName {
    Legacy(Relation),
    Apple,
}

#[derive(Clone, Copy)]
pub(super) enum Change {
    Set,
    Clear,
}

pub(super) enum Dialect {
    Rfc,
    Apple { next_item: u32 },
}

#[derive(Clone, Copy)]
enum Source {
    New,
    Same(usize),
    Other(usize),
}

impl Relation {
    pub(super) fn prop(self) -> PropId {
        match self {
            Relation::Child => CHILDRENS_NAMES,
            Relation::Spouse => SPOUSE_NAME,
            Relation::Manager => MANAGER_NAME,
            Relation::Assistant => ASSISTANT,
        }
    }

    fn related_params(self) -> Vec<VCardParameter> {
        let value = VCardParameter::value(VCardValueType::Text);
        match self {
            Relation::Child => vec![value, VCardParameter::typ(VCardType::Child)],
            Relation::Spouse => vec![value, VCardParameter::typ(VCardType::Spouse)],
            Relation::Manager => vec![
                value,
                VCardParameter::typ(MANAGER_TYPE.to_string()),
                VCardParameter::typ(VCardType::CoWorker),
            ],
            Relation::Assistant => vec![
                value,
                VCardParameter::typ(ASSISTANT_TYPE.to_string()),
                VCardParameter::typ(VCardType::CoWorker),
            ],
        }
    }

    fn label(self) -> &'static str {
        match self {
            Relation::Child => "_$!<Child>!$_",
            Relation::Spouse => "_$!<Spouse>!$_",
            Relation::Manager => "_$!<Manager>!$_",
            Relation::Assistant => "_$!<Assistant>!$_",
        }
    }
}

impl OtherName {
    pub(super) fn classify(
        self,
        entry: &VCardEntry,
        labels: &Labels<'_>,
    ) -> Option<(Relation, Form)> {
        match self {
            OtherName::Legacy(relation) => Some((relation, Form::Legacy)),
            OtherName::Apple => labels.get(entry.group.as_deref()?),
        }
    }
}

impl Dialect {
    pub(super) fn of(card: &VCard) -> Self {
        if card.version() != Some(VCardVersion::V3_0) {
            return Dialect::Rfc;
        }
        let last = card
            .entries
            .iter()
            .filter_map(|entry| item_number(entry.group.as_deref()?))
            .max()
            .unwrap_or_default();
        match last.checked_add(1) {
            Some(next_item) => Dialect::Apple { next_item },
            None => Dialect::Rfc,
        }
    }

    fn entry(&mut self, relation: Relation, name: String) -> (VCardEntry, Option<VCardEntry>) {
        let values = smallvec![VCardValue::Text(name)];
        match self {
            Dialect::Rfc => (
                VCardEntry {
                    group: None,
                    name: VCardProperty::Related,
                    params: relation.related_params(),
                    values,
                },
                None,
            ),
            Dialect::Apple { next_item } => {
                let item = *next_item;
                match item.checked_add(1) {
                    Some(next) => *next_item = next,
                    None => *self = Dialect::Rfc,
                }
                let group = format!("{ITEM_GROUP}{item}");
                let label = VCardEntry {
                    group: Some(group.clone()),
                    name: VCardProperty::Other(LABEL_PROPERTY.into()),
                    params: Vec::new(),
                    values: smallvec![VCardValue::Text(relation.label().into())],
                };
                (
                    VCardEntry {
                        group: Some(group),
                        name: VCardProperty::Other(APPLE_PROPERTY.into()),
                        params: Vec::new(),
                        values,
                    },
                    Some(label),
                )
            }
        }
    }

    pub(super) fn push(&mut self, entries: &mut Vec<VCardEntry>, relation: Relation, name: String) {
        let (entry, label) = self.entry(relation, name);
        entries.push(entry);
        entries.extend(label);
    }
}

fn item_number(group: &str) -> Option<u32> {
    let (prefix, digits) = group.split_at_checked(ITEM_GROUP.len())?;
    if !prefix.eq_ignore_ascii_case(ITEM_GROUP)
        || digits.is_empty()
        || !digits.bytes().all(|byte| byte.is_ascii_digit())
    {
        return None;
    }
    digits.parse().ok()
}

#[derive(Default)]
pub(super) struct Labels<'e>(Vec<(&'e str, Relation, Form)>);

impl<'e> Labels<'e> {
    pub(super) fn new(entries: &'e [VCardEntry]) -> Self {
        let mut labels: Vec<_> = entries
            .iter()
            .filter_map(|entry| {
                let group = entry.group.as_deref()?;
                if !is_label(entry) {
                    return None;
                }
                let label = entry.values.first()?.as_text()?;
                hashify::map_ignore_case!(label.as_bytes(), (Relation, Form),
                    "_$!<Child>!$_" => (Relation::Child, Form::Apple),
                    "_$!<Spouse>!$_" => (Relation::Spouse, Form::Apple),
                    "_$!<Partner>!$_" => (Relation::Spouse, Form::Partner),
                    "_$!<Manager>!$_" => (Relation::Manager, Form::Apple),
                    "_$!<Assistant>!$_" => (Relation::Assistant, Form::Apple),
                )
                .map(|(relation, form)| (group, *relation, *form))
            })
            .collect();
        labels.sort_unstable_by(|(a, ..), (b, ..)| cmp_ignore_case(a, b));
        Labels(labels)
    }

    fn get(&self, group: &str) -> Option<(Relation, Form)> {
        let index = self
            .0
            .binary_search_by(|(known, ..)| cmp_ignore_case(known, group))
            .ok()?;
        self.0
            .get(index)
            .map(|(_, relation, form)| (*relation, *form))
    }
}

fn cmp_ignore_case(a: &str, b: &str) -> Ordering {
    a.bytes()
        .map(|byte| byte.to_ascii_lowercase())
        .cmp(b.bytes().map(|byte| byte.to_ascii_lowercase()))
}

fn cmp_exact(a: &str, b: &str) -> Ordering {
    a.cmp(b)
}

fn cmp_loose(a: &str, b: &str) -> Ordering {
    cmp_ignore_case(a.trim(), b.trim())
}

fn is_label(entry: &VCardEntry) -> bool {
    matches!(&entry.name, VCardProperty::Other(name)
        if hashify::set_ignore_case!(name.as_bytes(), "X-ABLABEL"))
}

fn classify(entry: &VCardEntry, labels: &Labels<'_>) -> Option<(Relation, Form)> {
    match &entry.name {
        VCardProperty::Related => related_name(entry).map(|relation| (relation, Form::Related)),
        VCardProperty::Other(name) => {
            relation_property!(name, [OtherName], [identity])?.classify(entry, labels)
        }
        _ => None,
    }
}

pub(super) fn related_name(entry: &VCardEntry) -> Option<Relation> {
    let mut relation = None;
    let mut value_type = None;
    for param in &entry.params {
        match &param.value {
            VCardParameterValue::Type(VCardType::Child) => {
                relation = relation.or(Some(Relation::Child))
            }
            VCardParameterValue::Type(VCardType::Spouse) => {
                relation = relation.or(Some(Relation::Spouse))
            }
            VCardParameterValue::Text(text) if param.name == VCardParameterName::Type => {
                relation = relation.or_else(|| {
                    hashify::map_ignore_case!(text.as_bytes(), Relation,
                        "manager" => Relation::Manager,
                        "assistant" => Relation::Assistant,
                    )
                    .copied()
                })
            }
            VCardParameterValue::ValueType(value) => value_type = Some(value),
            _ => {}
        }
    }
    let is_name = match value_type {
        Some(value) => matches!(value, VCardValueType::Text),
        None => entry
            .values
            .first()
            .and_then(VCardValue::as_text)
            .is_some_and(|text| uri_scheme(text).is_none()),
    };
    relation.filter(|_| is_name)
}

pub(super) fn mark_text(entry: &mut VCardEntry) {
    if matches!(entry.name, VCardProperty::Related)
        && !entry
            .params
            .iter()
            .any(|param| matches!(param.name, VCardParameterName::Value))
    {
        entry
            .params
            .push(VCardParameter::value(VCardValueType::Text));
    }
}

pub(super) fn remove_relation(
    entries: &[VCardEntry],
    relation: Relation,
    origin: Option<usize>,
    change: Change,
    removed: &mut Vec<usize>,
) -> Option<usize> {
    let labels = Labels::new(entries);
    let mut keep = None;
    let mut orphans = Vec::new();
    for (index, entry) in entries.iter().enumerate() {
        match classify(entry, &labels) {
            Some((found, form)) if found == relation => {
                let is_origin = origin == Some(index);
                if is_origin
                    && keep.is_none()
                    && matches!(change, Change::Set)
                    && form != Form::Legacy
                {
                    keep = Some(index);
                } else if is_origin || form != Form::Partner || matches!(change, Change::Clear) {
                    removed.push(index);
                    orphans.extend(entry.group.as_deref());
                }
            }
            _ => {}
        }
    }
    drop_labels(entries, orphans, removed);
    keep
}

pub(super) fn rewrite_children(card: &mut VCard, names: Vec<String>, removed: &mut Vec<usize>) {
    let mut slots: SmallVec<[usize; 4]> = SmallVec::new();
    let mut sources: SmallVec<[Source; 4]> = smallvec![Source::New; names.len()];
    {
        let entries = &card.entries;
        let labels = Labels::new(entries);
        let mut orphans = Vec::new();
        for (index, entry) in entries.iter().enumerate() {
            match classify(entry, &labels) {
                Some((Relation::Child, Form::Legacy)) => {
                    removed.push(index);
                    orphans.extend(entry.group.as_deref());
                }
                Some((Relation::Child, _)) => slots.push(index),
                _ => {}
            }
        }
        let mut used: SmallVec<[bool; 4]> = smallvec![false; slots.len()];
        if !slots.is_empty() && !names.is_empty() {
            let values: SmallVec<[Option<&str>; 4]> = slots
                .iter()
                .map(|index| {
                    entries
                        .get(*index)
                        .and_then(|entry| entry.values.first())
                        .and_then(VCardValue::as_text)
                })
                .collect();
            reuse_by_name(&values, &names, &mut sources, &mut used, cmp_exact);
            reuse_by_name(&values, &names, &mut sources, &mut used, cmp_loose);
        }
        let mut free = used
            .iter()
            .enumerate()
            .filter(|(_, taken)| !**taken)
            .map(|(ordinal, _)| ordinal);
        for source in sources
            .iter_mut()
            .filter(|source| matches!(source, Source::New))
        {
            match free.next() {
                Some(ordinal) => *source = Source::Other(ordinal),
                None => break,
            }
        }
        orphans.extend(free.filter_map(|ordinal| {
            slots
                .get(ordinal)
                .and_then(|index| entries.get(*index))
                .and_then(|entry| entry.group.as_deref())
        }));
        removed.extend(slots.iter().skip(names.len()));
        drop_labels(entries, orphans, removed);
    }
    let mut dialect = if sources.iter().any(|source| matches!(source, Source::New)) {
        Dialect::of(card)
    } else {
        Dialect::Rfc
    };
    let entries = &mut card.entries;
    let mut pool: SmallVec<[Option<VCardEntry>; 4]> = slots
        .iter()
        .map(|index| {
            entries
                .get_mut(*index)
                .map(|entry| mem::replace(entry, vacant()))
        })
        .collect();
    let mut positions = slots.iter();
    for (name, source) in names.into_iter().zip(sources) {
        let reused = match source {
            Source::New => None,
            Source::Same(ordinal) => pool.get_mut(ordinal).and_then(Option::take),
            Source::Other(ordinal) => {
                pool.get_mut(ordinal)
                    .and_then(Option::take)
                    .map(|mut entry| {
                        entry.params.retain(|param| {
                            !matches!(
                                param.name,
                                VCardParameterName::Pid | VCardParameterName::Altid
                            )
                        });
                        entry
                    })
            }
        };
        let (entry, label) = match reused {
            Some(mut entry) => {
                entry.values = smallvec![VCardValue::Text(name)];
                mark_text(&mut entry);
                (entry, None)
            }
            None => dialect.entry(Relation::Child, name),
        };
        match positions.next().and_then(|index| entries.get_mut(*index)) {
            Some(slot) => *slot = entry,
            None => entries.push(entry),
        }
        entries.extend(label);
    }
}

fn reuse_by_name(
    values: &[Option<&str>],
    names: &[String],
    sources: &mut [Source],
    used: &mut [bool],
    cmp: fn(&str, &str) -> Ordering,
) {
    if !sources.iter().any(|source| matches!(source, Source::New)) {
        return;
    }
    let mut order: SmallVec<[(&str, usize); 4]> = values
        .iter()
        .zip(used.iter())
        .enumerate()
        .filter_map(|(ordinal, (value, taken))| {
            value.filter(|_| !*taken).map(|value| (value, ordinal))
        })
        .collect();
    if order.is_empty() {
        return;
    }
    order.sort_unstable_by(|(a, first), (b, second)| cmp(a, b).then(first.cmp(second)));
    let mut consumed: SmallVec<[usize; 4]> = smallvec![0; order.len()];
    for (name, source) in names.iter().zip(sources.iter_mut()) {
        if !matches!(source, Source::New) {
            continue;
        }
        let start = order.partition_point(|(value, _)| cmp(value, name).is_lt());
        let Some(count) = consumed.get_mut(start) else {
            continue;
        };
        if let Some((value, ordinal)) = order.get(start + *count)
            && cmp(value, name).is_eq()
            && let Some(taken) = used.get_mut(*ordinal)
        {
            *count += 1;
            *taken = true;
            *source = Source::Same(*ordinal);
        }
    }
}

fn vacant() -> VCardEntry {
    VCardEntry {
        group: None,
        name: VCardProperty::Related,
        params: Vec::new(),
        values: SmallVec::new(),
    }
}

fn drop_labels(entries: &[VCardEntry], mut orphans: Vec<&str>, removed: &mut Vec<usize>) {
    if orphans.is_empty() {
        return;
    }
    orphans.sort_unstable_by(|a, b| cmp_ignore_case(a, b));
    removed.extend(
        entries
            .iter()
            .enumerate()
            .filter(|(_, entry)| {
                is_label(entry)
                    && entry.group.as_deref().is_some_and(|group| {
                        orphans
                            .binary_search_by(|known| cmp_ignore_case(known, group))
                            .is_ok()
                    })
            })
            .map(|(index, _)| index),
    );
}
