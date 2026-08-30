/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: LicenseRef-SEL
 */

use std::{borrow::Cow, fmt};

use serde::{Deserialize, Deserializer, Serialize, Serializer, de::Visitor};

use crate::{
    MESSAGE_SEARCH_REQUEST, attributes::AttributeSelection, filter::Filter, json::scim_object,
    message::error::Error,
};

scim_object!(pub SearchRequest<'x>, Some(MESSAGE_SEARCH_REQUEST), {
    "attributes" => strs attributes: Option<Vec<Cow<'x, str>>>,
    "excludedAttributes" => strs excluded_attributes: Option<Vec<Cow<'x, str>>>,
    "filter" => str filter: Option<Cow<'x, str>>,
    "sortBy" => str sort_by: Option<Cow<'x, str>>,
    "sortOrder" => any sort_order: Option<SortOrder>,
    "startIndex" => any start_index: Option<i64>,
    "count" => any count: Option<i64>,
    "cursor" => str cursor: Option<Cow<'x, str>>,
});

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SortOrder {
    #[default]
    Ascending,
    Descending,
}

impl SortOrder {
    pub fn parse(value: &str) -> Option<Self> {
        hashify::tiny_map_ignore_case!(value.as_bytes(),
            "ascending" => SortOrder::Ascending,
            "descending" => SortOrder::Descending,
        )
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            SortOrder::Ascending => "ascending",
            SortOrder::Descending => "descending",
        }
    }

    pub fn is_descending(&self) -> bool {
        *self == SortOrder::Descending
    }
}

impl<'x> SearchRequest<'x> {
    pub fn parse(body: &'x [u8]) -> Result<Self, Error> {
        serde_json::from_slice(body).map_err(|err| Error::invalid_syntax(err.to_string()))
    }

    pub fn from_query(query: &'x str) -> Result<Self, Error> {
        let mut request = SearchRequest::default();

        for parameter in query.strip_prefix('?').unwrap_or(query).split('&') {
            if parameter.is_empty() {
                continue;
            }

            let (name, value) = match parameter.split_once('=') {
                Some((name, value)) => (name, decode(value)),
                None => (parameter, Cow::Borrowed("")),
            };

            match hashify::tiny_map_ignore_case!(name.as_bytes(),
                "attributes" => Parameter::Attributes,
                "excludedAttributes" => Parameter::ExcludedAttributes,
                "filter" => Parameter::Filter,
                "sortBy" => Parameter::SortBy,
                "sortOrder" => Parameter::SortOrder,
                "startIndex" => Parameter::StartIndex,
                "count" => Parameter::Count,
                "cursor" => Parameter::Cursor,
            ) {
                Some(Parameter::Attributes) => {
                    request.attributes = Some(split_list(value));
                }
                Some(Parameter::ExcludedAttributes) => {
                    request.excluded_attributes = Some(split_list(value));
                }
                Some(Parameter::Filter) => {
                    request.filter = Some(value);
                }
                Some(Parameter::SortBy) => {
                    request.sort_by = Some(value);
                }
                Some(Parameter::SortOrder) => {
                    request.sort_order = Some(SortOrder::parse(&value).ok_or_else(|| {
                        Error::invalid_value(format!("Invalid 'sortOrder' value '{value}'"))
                    })?);
                }
                Some(Parameter::StartIndex) => {
                    request.start_index = Some(parse_number(&value, "startIndex")?);
                }
                Some(Parameter::Count) => {
                    request.count = Some(parse_number(&value, "count").map_err(|_| {
                        Error::invalid_count(format!("Invalid 'count' value '{value}'"))
                    })?);
                }
                Some(Parameter::Cursor) => {
                    request.cursor = Some(value);
                }
                None => {}
            }
        }

        Ok(request)
    }

    pub fn parse_filter(&self) -> Result<Option<Filter<'_>>, Error> {
        match self.filter.as_deref() {
            Some(filter) if !filter.is_empty() => Filter::parse(filter).map(Some),
            _ => Ok(None),
        }
    }

    pub fn attribute_selection(&self) -> Result<AttributeSelection<'_>, Error> {
        AttributeSelection::from_lists(
            self.attributes.as_deref(),
            self.excluded_attributes.as_deref(),
        )
    }

    pub fn effective_start_index(&self) -> usize {
        self.start_index
            .map_or(1, |start_index| start_index.max(1) as usize)
    }

    pub fn effective_count(&self, default: usize, max: usize) -> usize {
        self.count
            .map_or(default, |count| count.max(0) as usize)
            .min(max)
    }

    pub fn is_cursor_paginated(&self) -> bool {
        self.cursor.is_some()
    }
}

fn parse_number(value: &str, name: &str) -> Result<i64, Error> {
    value
        .trim()
        .parse::<i64>()
        .map_err(|_| Error::invalid_value(format!("Invalid '{name}' value '{value}'")))
}

enum Parameter {
    Attributes,
    ExcludedAttributes,
    Filter,
    SortBy,
    SortOrder,
    StartIndex,
    Count,
    Cursor,
}

fn split_list(value: Cow<'_, str>) -> Vec<Cow<'_, str>> {
    match value {
        Cow::Borrowed(value) => value
            .split(',')
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(Cow::Borrowed)
            .collect(),
        Cow::Owned(value) => value
            .split(',')
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(|value| Cow::Owned(value.to_string()))
            .collect(),
    }
}

fn decode(value: &str) -> Cow<'_, str> {
    let bytes = value.as_bytes();

    if !bytes.iter().any(|ch| matches!(ch, b'%' | b'+')) {
        return Cow::Borrowed(value);
    }

    let mut result = Vec::with_capacity(bytes.len());
    let mut pos = 0;

    while pos < bytes.len() {
        match bytes[pos] {
            b'%' => {
                match value
                    .get(pos + 1..pos + 3)
                    .filter(|digits| digits.bytes().all(|ch| ch.is_ascii_hexdigit()))
                    .and_then(|digits| u8::from_str_radix(digits, 16).ok())
                {
                    Some(byte) => {
                        result.push(byte);
                        pos += 3;
                    }
                    None => {
                        result.push(b'%');
                        pos += 1;
                    }
                }
            }
            b'+' => {
                result.push(b' ');
                pos += 1;
            }
            byte => {
                result.push(byte);
                pos += 1;
            }
        }
    }

    Cow::Owned(
        String::from_utf8(result)
            .unwrap_or_else(|err| String::from_utf8_lossy(err.as_bytes()).into_owned()),
    )
}

impl Serialize for SortOrder {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for SortOrder {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct SortOrderVisitor;

        impl<'de> Visitor<'de> for SortOrderVisitor {
            type Value = SortOrder;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("'ascending' or 'descending'")
            }

            fn visit_str<E: serde::de::Error>(self, v: &str) -> Result<Self::Value, E> {
                SortOrder::parse(v)
                    .ok_or_else(|| E::custom(format!("Invalid 'sortOrder' value '{v}'")))
            }
        }

        deserializer.deserialize_str(SortOrderVisitor)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_search_request() {
        let request = SearchRequest::parse(
            br#"{
                "schemas": ["urn:ietf:params:scim:api:messages:2.0:SearchRequest"],
                "attributes": ["displayName", "userName"],
                "filter": "displayName sw \"smith\"",
                "startIndex": 1,
                "count": 10
            }"#,
        )
        .unwrap();

        assert_eq!(
            request.attributes.as_deref(),
            Some(["displayName".into(), "userName".into()].as_slice())
        );
        assert_eq!(request.filter.as_deref(), Some(r#"displayName sw "smith""#));
        assert_eq!(request.start_index, Some(1));
        assert_eq!(request.count, Some(10));
    }

    #[test]
    fn reject_wrong_schema_uri() {
        let error = SearchRequest::parse(
            br#"{"schemas": ["urn:ietf:params:scim:api:messages:2.0:BulkRequest"]}"#,
        )
        .unwrap_err();

        assert_eq!(error.status, 400);
        assert_eq!(
            error.scim_type,
            Some(crate::message::error::ScimType::InvalidSyntax)
        );
    }

    #[test]
    fn parse_query_string() {
        let request = SearchRequest::from_query(
            "filter=userName%20eq%20%22alice%40corp.example%22&startIndex=1&count=100\
             &sortBy=userName&sortOrder=descending&attributes=userName,active",
        )
        .unwrap();

        assert_eq!(
            request.filter.as_deref(),
            Some(r#"userName eq "alice@corp.example""#)
        );
        assert_eq!(request.start_index, Some(1));
        assert_eq!(request.count, Some(100));
        assert_eq!(request.sort_by.as_deref(), Some("userName"));
        assert_eq!(request.sort_order, Some(SortOrder::Descending));
        assert_eq!(
            request.attributes.as_deref(),
            Some(["userName".into(), "active".into()].as_slice())
        );
    }

    #[test]
    fn parse_query_string_with_plus_encoding() {
        let request = SearchRequest::from_query("filter=userName+eq+%22a+b%22").unwrap();

        assert_eq!(request.filter.as_deref(), Some(r#"userName eq "a b""#));
    }

    #[test]
    fn cursor_pagination_parameters() {
        let request = SearchRequest::from_query("cursor&count=10").unwrap();

        assert!(request.is_cursor_paginated());
        assert_eq!(request.cursor.as_deref(), Some(""));

        let request = SearchRequest::from_query("cursor=VZUTiyhEQJ94IR&count=10").unwrap();
        assert_eq!(request.cursor.as_deref(), Some("VZUTiyhEQJ94IR"));

        let request = SearchRequest::from_query("count=10").unwrap();
        assert!(!request.is_cursor_paginated());
    }

    #[test]
    fn unknown_query_parameters_are_ignored() {
        let request = SearchRequest::from_query("excludedAttributes=members&unknown=1").unwrap();

        assert_eq!(
            request.excluded_attributes.as_deref(),
            Some(["members".into()].as_slice())
        );
    }

    #[test]
    fn invalid_query_parameters() {
        use crate::message::error::ScimType;

        for (query, scim_type) in [
            ("startIndex=abc", ScimType::InvalidValue),
            ("sortOrder=sideways", ScimType::InvalidValue),
            ("count=1.5", ScimType::InvalidCount),
        ] {
            let error = SearchRequest::from_query(query).unwrap_err();

            assert_eq!(error.status, 400, "{query}");
            assert_eq!(error.scim_type, Some(scim_type), "{query}");
        }
    }

    #[test]
    fn query_strings_may_carry_their_question_mark() {
        let request = SearchRequest::from_query("?count=5&sortBy=userName").unwrap();

        assert_eq!(request.count, Some(5));
        assert_eq!(request.sort_by.as_deref(), Some("userName"));
    }

    #[test]
    fn query_parameter_names_are_case_insensitive() {
        let request = SearchRequest::from_query("Filter=title%20pr&StartIndex=3").unwrap();

        assert_eq!(request.filter.as_deref(), Some("title pr"));
        assert_eq!(request.start_index, Some(3));
    }

    #[test]
    fn query_values_are_borrowed_when_not_encoded() {
        let request =
            SearchRequest::from_query("sortBy=userName&attributes=userName,active").unwrap();

        assert!(matches!(request.sort_by, Some(Cow::Borrowed(_))));
        assert!(matches!(
            request.attributes.as_deref(),
            Some([Cow::Borrowed(_), Cow::Borrowed(_)])
        ));
    }

    #[test]
    fn cursor_timeout_is_not_a_request_parameter() {
        assert!(
            SearchRequest::parse(
                br#"{"schemas": ["urn:ietf:params:scim:api:messages:2.0:SearchRequest"],
                     "cursorTimeout": 3600}"#
            )
            .is_err()
        );
    }

    #[test]
    fn missing_schema_uri_is_rejected() {
        let error = SearchRequest::parse(br#"{"count": 10}"#).unwrap_err();

        assert_eq!(error.status, 400);
        assert!(
            error.detail.as_deref().unwrap().contains("schemas"),
            "{error}"
        );
    }

    #[test]
    fn pagination_defaults() {
        let request = SearchRequest::from_query("").unwrap();
        assert_eq!(request.effective_start_index(), 1);
        assert_eq!(request.effective_count(100, 200), 100);

        let request = SearchRequest::from_query("startIndex=0").unwrap();
        assert_eq!(request.effective_start_index(), 1);

        let request = SearchRequest::from_query("startIndex=-5").unwrap();
        assert_eq!(request.effective_start_index(), 1);

        let request = SearchRequest::from_query("count=1000").unwrap();
        assert_eq!(request.effective_count(100, 200), 200);

        let request = SearchRequest::from_query("count=0").unwrap();
        assert_eq!(request.effective_count(100, 200), 0);

        let request = SearchRequest::from_query("count=-1").unwrap();
        assert_eq!(request.effective_count(100, 200), 0);
    }

    #[test]
    fn filter_and_attributes_are_resolved() {
        let request =
            SearchRequest::from_query("filter=userName%20eq%20%22a%22&attributes=userName")
                .unwrap();

        assert!(request.parse_filter().unwrap().is_some());
        assert!(matches!(
            request.attribute_selection().unwrap(),
            AttributeSelection::Include(_)
        ));

        let request = SearchRequest::from_query("").unwrap();
        assert!(request.parse_filter().unwrap().is_none());
        assert!(request.attribute_selection().unwrap().is_default());
    }

    #[test]
    fn mutually_exclusive_attribute_parameters() {
        let request =
            SearchRequest::from_query("attributes=userName&excludedAttributes=groups").unwrap();

        assert!(request.attribute_selection().is_err());
    }

    #[test]
    fn serialize_search_request() {
        let request = SearchRequest {
            filter: Some(r#"userName eq "a""#.into()),
            count: Some(10),
            sort_order: Some(SortOrder::Ascending),
            ..Default::default()
        };

        assert_eq!(
            serde_json::to_value(&request).unwrap(),
            serde_json::json!({
                "schemas": ["urn:ietf:params:scim:api:messages:2.0:SearchRequest"],
                "filter": "userName eq \"a\"",
                "sortOrder": "ascending",
                "count": 10
            })
        );
    }
}
