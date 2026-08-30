/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: LicenseRef-SEL
 */

use std::borrow::Cow;

use serde::{Serialize, Serializer, ser::SerializeMap};

use crate::MESSAGE_LIST_RESPONSE;

#[derive(Debug, Clone, PartialEq)]
pub struct ListResponse<'x, T> {
    pub total_results: usize,
    pub items_per_page: Option<usize>,
    pub start_index: Option<usize>,
    pub next_cursor: Option<Cow<'x, str>>,
    pub previous_cursor: Option<Cow<'x, str>>,
    pub resources: Vec<T>,
}

impl<'x, T> ListResponse<'x, T> {
    pub fn new(total_results: usize, resources: Vec<T>) -> Self {
        ListResponse {
            total_results,
            items_per_page: Some(resources.len()),
            start_index: None,
            next_cursor: None,
            previous_cursor: None,
            resources,
        }
    }

    pub fn with_start_index(mut self, start_index: usize) -> Self {
        self.start_index = Some(start_index);
        self
    }

    pub fn with_next_cursor(mut self, next_cursor: impl Into<Cow<'x, str>>) -> Self {
        self.next_cursor = Some(next_cursor.into());
        self
    }

    pub fn with_previous_cursor(mut self, previous_cursor: impl Into<Cow<'x, str>>) -> Self {
        self.previous_cursor = Some(previous_cursor.into());
        self
    }
}

impl<T> Default for ListResponse<'_, T> {
    fn default() -> Self {
        ListResponse {
            total_results: 0,
            items_per_page: Some(0),
            start_index: None,
            next_cursor: None,
            previous_cursor: None,
            resources: Vec::new(),
        }
    }
}

impl<T: Serialize> Serialize for ListResponse<'_, T> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut map = serializer.serialize_map(None)?;
        map.serialize_entry("schemas", &[MESSAGE_LIST_RESPONSE])?;
        map.serialize_entry("totalResults", &self.total_results)?;
        if let Some(items_per_page) = self.items_per_page {
            map.serialize_entry("itemsPerPage", &items_per_page)?;
        }
        if let Some(start_index) = self.start_index {
            map.serialize_entry("startIndex", &start_index)?;
        }
        if let Some(next_cursor) = &self.next_cursor {
            map.serialize_entry("nextCursor", next_cursor)?;
        }
        if let Some(previous_cursor) = &self.previous_cursor {
            map.serialize_entry("previousCursor", previous_cursor)?;
        }
        map.serialize_entry("Resources", &self.resources)?;
        map.end()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn serialize_index_paged_response() {
        let response = ListResponse::new(100, vec!["a", "b"]).with_start_index(1);

        assert_eq!(
            serde_json::to_value(&response).unwrap(),
            serde_json::json!({
                "schemas": ["urn:ietf:params:scim:api:messages:2.0:ListResponse"],
                "totalResults": 100,
                "itemsPerPage": 2,
                "startIndex": 1,
                "Resources": ["a", "b"]
            })
        );
    }

    #[test]
    fn serialize_cursor_paged_response() {
        let response = ListResponse::new(100, vec!["a"]).with_next_cursor("VZUTiyhEQJ94IR");
        let value = serde_json::to_value(&response).unwrap();

        assert_eq!(value["nextCursor"], "VZUTiyhEQJ94IR");
        assert!(value.get("previousCursor").is_none());
        assert!(value.get("startIndex").is_none());
    }

    #[test]
    fn empty_result_sets_are_valid() {
        let response = ListResponse::<&str>::default().with_start_index(1);

        assert_eq!(
            serde_json::to_value(&response).unwrap(),
            serde_json::json!({
                "schemas": ["urn:ietf:params:scim:api:messages:2.0:ListResponse"],
                "totalResults": 0,
                "itemsPerPage": 0,
                "startIndex": 1,
                "Resources": []
            })
        );
    }

    #[test]
    fn resources_uses_a_capital_r() {
        let json = serde_json::to_string(&ListResponse::new(1, vec!["a"])).unwrap();

        assert!(json.contains(r#""Resources":["a"]"#), "{json}");
    }
}
