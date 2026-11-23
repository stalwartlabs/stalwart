/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    convert::{
        model::PropBag,
        tags::{BODY, IMPORTANCE, KEYWORDS_NAME, SENSITIVITY, SUBJECT},
    },
    ews::{
        schema::{BodyType, Importance, Sensitivity, UnindexedField},
        types::{item::ItemFields, xprop::ExtendedProperty},
    },
    mapi::prop::{OwnedPropValue, PropKey, PropKeyRef, PropType, sets::PS_PUBLIC_STRINGS},
};
use calcard::icalendar::{ICalendarComponent, ICalendarProperty};
use mail_parser::html_to_text;
use std::borrow::Cow;

pub(crate) const KEYWORDS: PropKeyRef<'static> = PropKeyRef::Name {
    set: PS_PUBLIC_STRINGS,
    name: KEYWORDS_NAME,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CommonField {
    Applied,
    MissingValue,
    NotCommon,
}

pub(crate) fn common_field(
    props: &mut PropBag,
    field: UnindexedField,
    item: Option<&ItemFields<'_>>,
) -> CommonField {
    let (key, value) = match field {
        UnindexedField::ItemSubject => match item.map(|item| item.subject.as_deref()) {
            Some(None) => return CommonField::MissingValue,
            Some(Some(text)) => (PropKeyRef::Tag(SUBJECT), unicode(text)),
            None => (PropKeyRef::Tag(SUBJECT), unicode("")),
        },
        UnindexedField::ItemBody => match item.map(|item| item.body.as_ref()) {
            Some(None) => return CommonField::MissingValue,
            Some(Some(body)) => {
                let text = match body.body_type {
                    BodyType::Html => Cow::Owned(html_to_text(&body.text)),
                    BodyType::Text => Cow::Borrowed(body.text.as_ref()),
                };
                (PropKeyRef::Tag(BODY), unicode(&text))
            }
            None => (PropKeyRef::Tag(BODY), unicode("")),
        },
        UnindexedField::ItemCategories => {
            let names = match item.map(|item| item.categories.as_ref()) {
                Some(None) => return CommonField::MissingValue,
                Some(Some(names)) => names
                    .0
                    .iter()
                    .map(|name| Box::from(name.as_ref()))
                    .collect(),
                None => Box::default(),
            };
            (KEYWORDS, OwnedPropValue::MvUnicode(names))
        }
        UnindexedField::ItemSensitivity => {
            let level = match item.map(|item| item.sensitivity) {
                Some(None) => return CommonField::MissingValue,
                Some(Some(Sensitivity::Personal)) => 1,
                Some(Some(Sensitivity::Private)) => 2,
                Some(Some(Sensitivity::Confidential)) => 3,
                Some(Some(Sensitivity::Normal)) | None => 0,
            };
            (PropKeyRef::Tag(SENSITIVITY), OwnedPropValue::I32(level))
        }
        UnindexedField::ItemImportance => {
            let level = match item.map(|item| item.importance) {
                Some(None) => return CommonField::MissingValue,
                Some(Some(Importance::Low)) => 0,
                Some(Some(Importance::High)) => 2,
                Some(Some(Importance::Normal)) | None => 1,
            };
            (PropKeyRef::Tag(IMPORTANCE), OwnedPropValue::I32(level))
        }
        _ => return CommonField::NotCommon,
    };
    props.set(key.to_key(), value);
    CommonField::Applied
}

pub(crate) fn extended_value(property: &ExtendedProperty<'_>) -> Option<(PropKey, OwnedPropValue)> {
    let (key, ptype) = property.uri.to_prop().ok()?;
    let value = property.value.to_owned_value(ptype).ok()?;
    Some((key, value))
}

pub(crate) fn cleared_value(ptype: PropType) -> OwnedPropValue {
    if ptype == PropType::Unicode {
        unicode("")
    } else {
        OwnedPropValue::Null
    }
}

pub(crate) fn with_appended_categories<'p>(
    props: &'p PropBag,
    appended: &[Box<str>],
    current: Option<&ICalendarComponent>,
) -> Cow<'p, PropBag> {
    with_appended_category_names(
        props,
        appended,
        current
            .into_iter()
            .flat_map(|component| component.entries.iter())
            .filter(|entry| entry.name == ICalendarProperty::Categories)
            .flat_map(|entry| entry.values.iter())
            .filter_map(|value| value.as_text()),
    )
}

pub(crate) fn with_appended_category_names<'p, 'c>(
    props: &'p PropBag,
    appended: &[Box<str>],
    current: impl Iterator<Item = &'c str>,
) -> Cow<'p, PropBag> {
    if appended.is_empty() {
        return Cow::Borrowed(props);
    }
    let mut names = match props.get(KEYWORDS, PropType::MvUnicode) {
        Some(OwnedPropValue::MvUnicode(names)) => names.to_vec(),
        _ => current.map(Box::from).collect(),
    };
    for name in appended {
        if !names.iter().any(|known| known.eq_ignore_ascii_case(name)) {
            names.push(name.clone());
        }
    }
    let mut props = props.clone();
    props.set(
        KEYWORDS.to_key(),
        OwnedPropValue::MvUnicode(names.into_boxed_slice()),
    );
    Cow::Owned(props)
}

fn unicode(text: &str) -> OwnedPropValue {
    OwnedPropValue::Unicode(Box::from(text))
}
