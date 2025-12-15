/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use ahash::AHashSet;
use serde_json::{Map, Value, json};

use crate::{
    backend::meili::{MeiliSearchResponse, MeiliSearchStore, main::assert_success},
    search::*,
    write::SearchIndex,
};
use std::fmt::{Display, Write};

impl MeiliSearchStore {
    pub async fn index(&self, documents: Vec<IndexDocument>) -> trc::Result<()> {
        let mut index_documents: [String; 5] = [
            String::new(),
            String::new(),
            String::new(),
            String::new(),
            String::new(),
        ];

        for document in documents {
            let request = &mut index_documents[document.index.array_pos()];
            if !request.is_empty() {
                request.push(',');
            } else {
                request.reserve(1024);
                request.push('[');
            }

            json_serialize(request, &document);
        }

        for (mut payload, index) in index_documents.into_iter().zip([
            SearchIndex::Email,
            SearchIndex::Calendar,
            SearchIndex::Contacts,
            SearchIndex::Tracing,
            SearchIndex::File,
        ]) {
            if payload.is_empty() {
                continue;
            }

            payload.push(']');

            let response = assert_success(
                self.client
                    .put(format!(
                        "{}/indexes/{}/documents",
                        self.url,
                        index.index_name()
                    ))
                    .body(payload)
                    .send()
                    .await,
            )
            .await?;
            self.wait_for_task(response).await?;
        }

        Ok(())
    }

    pub async fn query<R: SearchDocumentId>(
        &self,
        index: SearchIndex,
        filters: &[SearchFilter],
        sort: &[SearchComparator],
    ) -> trc::Result<Vec<R>> {
        let filter_group = build_query(filters);

        let mut body = Map::new();
        body.insert("limit".to_string(), Value::from(10_000));
        body.insert("offset".to_string(), Value::from(0));
        body.insert(
            "attributesToRetrieve".to_string(),
            Value::Array(vec![Value::String("id".to_string())]),
        );

        if !filter_group.filter.is_empty() {
            body.insert("filter".to_string(), Value::String(filter_group.filter));
        }

        if !filter_group.q.is_empty() {
            body.insert("q".to_string(), Value::String(filter_group.q));
        }

        if !sort.is_empty() {
            let sort_arr: Vec<Value> = sort
                .iter()
                .filter_map(|comp| match comp {
                    SearchComparator::Field { field, ascending } => Some(Value::String(format!(
                        "{}:{}",
                        field.field_name(),
                        if *ascending { "asc" } else { "desc" }
                    ))),
                    _ => None,
                })
                .collect();
            if !sort_arr.is_empty() {
                body.insert("sort".to_string(), Value::Array(sort_arr));
            }
        }

        let resp = assert_success(
            self.client
                .post(format!(
                    "{}/indexes/{}/search",
                    self.url,
                    index.index_name()
                ))
                .body(Value::Object(body).to_string())
                .send()
                .await,
        )
        .await?;

        let text = resp
            .text()
            .await
            .map_err(|err| trc::StoreEvent::MeilisearchError.reason(err))?;

        serde_json::from_str::<MeiliSearchResponse>(&text)
            .map(|results| {
                results
                    .hits
                    .into_iter()
                    .map(|hit| R::from_u64(hit.id))
                    .collect()
            })
            .map_err(|err| trc::StoreEvent::MeilisearchError.reason(err).details(text))
    }

    pub async fn unindex(&self, filter: SearchQuery) -> trc::Result<u64> {
        let filter_group = build_query(&filter.filters);

        if filter_group.filter.is_empty() {
            return Err(trc::StoreEvent::MeilisearchError.reason(
                "Meilisearch delete-by-filter requires structured (non-text) filters only",
            ));
        }

        let url = format!(
            "{}/indexes/{}/documents/delete",
            self.url,
            filter.index.index_name()
        );

        let response = assert_success(
            self.client
                .post(url)
                .body(json!({ "filter": filter_group.filter }).to_string())
                .send()
                .await,
        )
        .await?;

        self.wait_for_task(response).await?;

        Ok(0)
    }
}

#[derive(Default, Debug)]
struct FilterGroup {
    q: String,
    filter: String,
}

fn build_query(filters: &[SearchFilter]) -> FilterGroup {
    if filters.is_empty() {
        return FilterGroup::default();
    }
    let mut operator_stack = Vec::new();
    let mut operator = &SearchFilter::And;
    let mut is_first = true;
    let mut filter = String::new();
    let mut queries = AHashSet::new();

    for f in filters {
        match f {
            SearchFilter::Operator { field, op, value } => {
                if field.is_text() && matches!(op, SearchOperator::Equal | SearchOperator::Contains)
                {
                    let value = match value {
                        SearchValue::Text { value, .. } => value,
                        _ => {
                            debug_assert!(
                                false,
                                "Text field search with non-text value is not supported"
                            );
                            ""
                        }
                    };

                    if matches!(op, SearchOperator::Equal) {
                        queries.insert(format!("{value:?}"));
                    } else {
                        for token in value.split_whitespace() {
                            queries.insert(token.to_string());
                        }
                    }
                } else {
                    if !filter.is_empty() && !filter.ends_with('(') {
                        match operator {
                            SearchFilter::And => filter.push_str(" AND "),
                            SearchFilter::Or => filter.push_str(" OR "),
                            _ => (),
                        }
                    }

                    match value {
                        SearchValue::Text { value, .. } => {
                            filter.push_str(field.field_name());
                            filter.push(' ');
                            op.write_meli_op(&mut filter, format!("{value:?}"));
                        }
                        SearchValue::KeyValues(kv) => {
                            let (key, value) = kv.iter().next().unwrap();
                            filter.push_str(field.field_name());
                            filter.push('.');
                            filter.push_str(key);
                            filter.push(' ');
                            op.write_meli_op(&mut filter, format!("{value:?}"));
                        }
                        SearchValue::Int(v) => {
                            filter.push_str(field.field_name());
                            filter.push(' ');
                            op.write_meli_op(&mut filter, v);
                        }
                        SearchValue::Uint(v) => {
                            filter.push_str(field.field_name());
                            filter.push(' ');
                            op.write_meli_op(&mut filter, v);
                        }
                        SearchValue::Boolean(v) => {
                            filter.push_str(field.field_name());
                            filter.push(' ');
                            op.write_meli_op(&mut filter, v);
                        }
                    }
                }
            }
            SearchFilter::And | SearchFilter::Or => {
                if !filter.is_empty() && !filter.ends_with('(') {
                    match operator {
                        SearchFilter::And => filter.push_str(" AND "),
                        SearchFilter::Or => filter.push_str(" OR "),
                        _ => (),
                    }
                }

                operator_stack.push((operator, is_first));
                operator = f;
                is_first = true;
                filter.push('(');
            }
            SearchFilter::Not => {
                if !filter.is_empty() && !filter.ends_with('(') {
                    match operator {
                        SearchFilter::And => filter.push_str(" AND "),
                        SearchFilter::Or => filter.push_str(" OR "),
                        _ => (),
                    }
                }

                operator_stack.push((operator, is_first));
                operator = &SearchFilter::And;
                is_first = true;
                filter.push_str("NOT (");
            }
            SearchFilter::End => {
                let p = operator_stack.pop().unwrap_or((&SearchFilter::And, true));
                operator = p.0;
                is_first = p.1;

                if !filter.ends_with('(') {
                    filter.push(')');
                } else {
                    filter.pop();
                    if filter.ends_with("NOT ") {
                        let len = filter.len();
                        filter.truncate(len - 4);
                    }
                    if filter.ends_with(" AND ") {
                        let len = filter.len();
                        filter.truncate(len - 5);
                        is_first = true;
                    } else if filter.ends_with(" OR ") {
                        let len = filter.len();
                        filter.truncate(len - 4);
                        is_first = true;
                    }
                }
            }
            SearchFilter::DocumentSet(_) => {
                debug_assert!(false, "DocumentSet filters are not supported")
            }
        }
    }

    let mut q = String::new();
    if !queries.is_empty() {
        for (idx, term) in queries.into_iter().enumerate() {
            if idx > 0 {
                q.push(' ');
            }
            q.push_str(&term);
        }
    }

    FilterGroup { q, filter }
}

impl SearchOperator {
    fn write_meli_op(&self, query: &mut String, value: impl Display) {
        match self {
            SearchOperator::LowerThan => {
                let _ = write!(query, "< {value}");
            }
            SearchOperator::LowerEqualThan => {
                let _ = write!(query, "<= {value}");
            }
            SearchOperator::GreaterThan => {
                let _ = write!(query, "> {value}");
            }
            SearchOperator::GreaterEqualThan => {
                let _ = write!(query, ">= {value}");
            }
            SearchOperator::Equal | SearchOperator::Contains => {
                let _ = write!(query, "= {value}");
            }
        }
    }
}

fn json_serialize(request: &mut String, document: &IndexDocument) {
    let mut id = 0u64;
    let mut is_first = true;
    request.push('{');
    for (k, v) in document.fields.iter() {
        match k {
            SearchField::AccountId => {
                if let SearchValue::Uint(account_id) = v {
                    id |= account_id << 32;
                }
            }
            SearchField::DocumentId => {
                if let SearchValue::Uint(doc_id) = v {
                    id |= doc_id;
                }
            }
            SearchField::Id => {
                if let SearchValue::Uint(doc_id) = v {
                    id = *doc_id;
                }
                continue;
            }
            _ => {}
        }

        if !is_first {
            request.push(',');
        } else {
            is_first = false;
        }

        let _ = write!(request, "{:?}:", k.field_name());
        match v {
            SearchValue::Text { value, .. } => {
                json_serialize_str(request, value);
            }
            SearchValue::KeyValues(map) => {
                request.push('{');
                for (i, (key, value)) in map.iter().enumerate() {
                    if i > 0 {
                        request.push(',');
                    }
                    json_serialize_str(request, key);
                    request.push(':');
                    json_serialize_str(request, value);
                }
                request.push('}');
            }
            SearchValue::Int(v) => {
                let _ = write!(request, "{}", v);
            }
            SearchValue::Uint(v) => {
                let _ = write!(request, "{}", v);
            }
            SearchValue::Boolean(v) => {
                let _ = write!(request, "{}", v);
            }
        }
    }

    /*if id == 0 {
        debug_assert!(false, "Document is missing required ID fields");
    }*/

    let _ = write!(request, ",\"id\":{id}}}");
}

fn json_serialize_str(request: &mut String, value: &str) {
    request.push('"');
    for c in value.chars() {
        match c {
            '"' => request.push_str("\\\""),
            '\\' => request.push_str("\\\\"),
            '\n' => request.push_str("\\n"),
            '\r' => request.push_str("\\r"),
            '\t' => request.push_str("\\t"),
            '\u{0008}' => request.push_str("\\b"), // backspace
            '\u{000C}' => request.push_str("\\f"), // form feed
            _ => {
                if !c.is_control() {
                    request.push(c);
                } else {
                    let _ = write!(request, "\\u{:04x}", c as u32);
                }
            }
        }
    }
    request.push('"');
}

impl SearchIndex {
    #[inline(always)]
    fn array_pos(&self) -> usize {
        match self {
            SearchIndex::Email => 0,
            SearchIndex::Calendar => 1,
            SearchIndex::Contacts => 2,
            SearchIndex::Tracing => 3,
            SearchIndex::File => 4,
            SearchIndex::InMemory => unreachable!(),
        }
    }
}
