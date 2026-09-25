/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use jmap_tools::{Element, Key, Property};
use serde::{Serialize, Serializer};
use std::{borrow::Cow, str::FromStr};
use types::{id::Id, text::Text};

#[derive(Debug, Clone, Default)]
pub struct SearchSnippet;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SearchSnippetProperty {
    EmailId,
    Subject,
    Preview,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SearchSnippetValue {
    Id(Id),
}

impl Property for SearchSnippetProperty {
    fn try_parse(_: Option<&Key<'_, Self>>, value: &str) -> Option<Self> {
        SearchSnippetProperty::parse(value)
    }

    fn to_cow(&self) -> Cow<'static, str> {
        match self {
            SearchSnippetProperty::Preview => "preview",
            SearchSnippetProperty::Subject => "subject",
            SearchSnippetProperty::EmailId => "emailId",
        }
        .into()
    }

    fn key_eq(&self, other: &Self) -> bool {
        self == other
    }
}

impl Element for SearchSnippetValue {
    type Property = SearchSnippetProperty;

    fn try_parse<P>(key: &Key<'_, Self::Property>, value: &str) -> Option<Self> {
        if let Key::Property(prop) = key {
            match prop {
                SearchSnippetProperty::EmailId => {
                    Id::from_str(value).ok().map(SearchSnippetValue::Id)
                }
                _ => None,
            }
        } else {
            None
        }
    }

    fn to_cow(&self) -> Cow<'static, str> {
        self.text().to_cow()
    }

    fn serialize_text<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.text().serialize(serializer)
    }
}

impl SearchSnippetValue {
    pub fn text(&self) -> Text<'_> {
        match self {
            SearchSnippetValue::Id(id) => Text::Id(*id),
        }
    }
}

impl SearchSnippetProperty {
    fn parse(value: &str) -> Option<Self> {
        hashify::fnc_map!(value.as_bytes(),
            b"emailId" => Some(SearchSnippetProperty::EmailId),
            b"subject" => Some(SearchSnippetProperty::Subject),
            b"preview" => Some(SearchSnippetProperty::Preview),
            _ => None,
        )
    }
}
