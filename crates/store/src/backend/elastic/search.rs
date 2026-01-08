/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    backend::elastic::{
        DeleteByQueryResponse, ElasticSearchStore, SearchResponse, main::assert_success,
    },
    search::{
        IndexDocument, SearchComparator, SearchDocumentId, SearchField, SearchFilter,
        SearchOperator, SearchQuery, SearchValue,
    },
    write::SearchIndex,
};
use serde_json::{Map, Value, json};
use std::fmt::Write;

impl ElasticSearchStore {
    pub async fn index(&self, documents: Vec<IndexDocument>) -> trc::Result<()> {
        let mut request = String::with_capacity(512);

        for document in documents {
            let id = if let (Some(SearchValue::Uint(account_id)), Some(SearchValue::Uint(doc_id))) = (
                document.fields.get(&SearchField::AccountId),
                document.fields.get(&SearchField::DocumentId),
            ) {
                *account_id << 32 | *doc_id
            } else if let Some(SearchValue::Uint(id)) = document.fields.get(&SearchField::Id) {
                *id
            } else {
                debug_assert!(false, "Document is missing required ID fields");
                continue;
            };

            let _ = writeln!(
                &mut request,
                "{{\"index\":{{\"_index\":\"{}\",\"_id\":{id}}}}}",
                document.index.index_name()
            );
            json_serialize(&mut request, &document);
            request.push('\n');
        }

        assert_success(
            self.client
                .post(format!("{}/_bulk", self.url))
                .body(request)
                .send()
                .await,
        )
        .await
        .map(|_| ())
    }

    pub async fn query<R: SearchDocumentId>(
        &self,
        index: SearchIndex,
        filters: &[SearchFilter],
        sort: &[SearchComparator],
    ) -> trc::Result<Vec<R>> {
        let mut search_after: Option<Value> = None;
        let mut results = Vec::new();
        let mut has_more = true;

        while has_more {
            let query = Map::from_iter(
                [
                    Some(("query".to_string(), build_query(filters))),
                    Some(("size".to_string(), Value::from(10_000))),
                    Some(("_source".to_string(), Value::from(false))),
                    Some((
                        "sort".to_string(),
                        build_sort(sort, R::field().field_name()),
                    )),
                    search_after
                        .take()
                        .map(|sa| ("search_after".to_string(), sa)),
                ]
                .into_iter()
                .flatten(),
            );

            let response = assert_success(
                self.client
                    .post(format!("{}/{}/_search", self.url, index.index_name()))
                    .body(serde_json::to_string(&query).unwrap_or_default())
                    .send()
                    .await,
            )
            .await?;

            let text = response
                .text()
                .await
                .map_err(|err| trc::StoreEvent::ElasticsearchError.reason(err))?;

            let response = serde_json::from_str::<SearchResponse>(&text).map_err(|err| {
                trc::StoreEvent::ElasticsearchError
                    .reason(err)
                    .details(text)
            })?;

            has_more = response.hits.hits.len() == 10_000
                && response.hits.hits.last().unwrap().sort.is_some();

            for hit in response.hits.hits {
                search_after = hit.sort;
                results.push(R::from_u64(hit.id));
            }
        }

        Ok(results)
    }

    pub async fn unindex(&self, filter: SearchQuery) -> trc::Result<u64> {
        if filter.filters.is_empty() {
            return Err(trc::StoreEvent::ElasticsearchError
                .reason("Unindex operation requires at least one filter"));
        }

        let query = json!({
            "query": build_query(&filter.filters),
        });

        let response = assert_success(
            self.client
                .post(format!(
                    "{}/{}/_delete_by_query",
                    self.url,
                    filter.index.index_name()
                ))
                .body(serde_json::to_string(&query).unwrap_or_default())
                .send()
                .await,
        )
        .await?;

        let response_body = response
            .text()
            .await
            .map_err(|err| trc::StoreEvent::ElasticsearchError.reason(err))?;

        serde_json::from_str::<DeleteByQueryResponse>(&response_body)
            .map(|delete_response| delete_response.deleted)
            .map_err(|err| trc::StoreEvent::ElasticsearchError.reason(err))
    }

    pub async fn refresh_index(&self, index: SearchIndex) -> trc::Result<()> {
        let url = format!("{}/{}/_refresh", self.url, index.index_name());

        assert_success(self.client.post(url).send().await)
            .await
            .map(|_| ())
    }
}

fn build_query(filters: &[SearchFilter]) -> Value {
    if filters.is_empty() {
        return json!({ "match_all": {} });
    }

    let mut stack = Vec::new();
    let mut conditions = Vec::new();
    let mut logical_op = &SearchFilter::And;

    for filter in filters {
        match filter {
            SearchFilter::Operator { field, op, value } => {
                if field.is_text() && matches!(op, SearchOperator::Equal | SearchOperator::Contains)
                {
                    let SearchValue::Text { value, .. } = value else {
                        debug_assert!(false, "Invalid value type for text field");
                        continue;
                    };

                    if op != &SearchOperator::Equal {
                        conditions.push(json!({
                            "match": { field.field_name(): {
                                "query": value,
                                "operator": "and"
                            } }
                        }));
                    } else {
                        conditions.push(json!({
                            "match_phrase": { field.field_name(): value }
                        }));
                    }
                } else {
                    let value = match value {
                        SearchValue::Text { value, .. } => json!(value),
                        SearchValue::Int(value) => json!(value),
                        SearchValue::Uint(value) => json!(value),
                        SearchValue::Boolean(value) => json!(value),
                        SearchValue::KeyValues(kv) => {
                            let (key, value) = kv.iter().next().unwrap();

                            let cond = if !value.is_empty() {
                                if op == &SearchOperator::Equal {
                                    json!({
                                        "term": {
                                            format!("{}.{}.keyword", field.field_name(), key): value
                                        }
                                    })
                                } else {
                                    json!({
                                        "match": {
                                            format!("{}.{}", field.field_name(), key): value
                                        }
                                    })
                                }
                            } else {
                                json!({
                                    "exists": { "field": format!("{}.{}", field.field_name(), key) }
                                })
                            };

                            conditions.push(cond);
                            continue;
                        }
                    };

                    let cond = match op {
                        SearchOperator::Equal | SearchOperator::Contains => json!({
                            "term": { field.field_name(): value }
                        }),
                        op => {
                            let op = match op {
                                SearchOperator::LowerThan => "lt",
                                SearchOperator::LowerEqualThan => "lte",
                                SearchOperator::GreaterThan => "gt",
                                SearchOperator::GreaterEqualThan => "gte",
                                _ => unreachable!(),
                            };

                            json!({
                                "range": { field.field_name(): { op: value } }
                            })
                        }
                    };

                    conditions.push(cond);
                }
            }

            SearchFilter::And | SearchFilter::Or | SearchFilter::Not => {
                stack.push((logical_op, conditions));
                logical_op = filter;
                conditions = Vec::new();
            }
            SearchFilter::End => {
                if let Some((prev_logical_op, mut prev_conditions)) = stack.pop() {
                    if !conditions.is_empty() {
                        match logical_op {
                            SearchFilter::And => {
                                prev_conditions.push(json!({ "bool": { "must": conditions } }));
                            }
                            SearchFilter::Or => {
                                prev_conditions.push(json!({ "bool": { "should": conditions } }));
                            }
                            SearchFilter::Not => {
                                prev_conditions.push(json!({ "bool": { "must_not": conditions } }));
                            }
                            _ => unreachable!(),
                        }
                    }
                    logical_op = prev_logical_op;
                    conditions = prev_conditions;
                }
            }
            SearchFilter::DocumentSet(_) => {
                debug_assert!(
                    false,
                    "DocumentSet filters are not supported in this backend"
                );
                continue;
            }
        }
    }

    debug_assert!(
        !conditions.is_empty(),
        "No conditions were built for the query"
    );

    if conditions.len() == 1 {
        conditions.pop().unwrap()
    } else {
        json!({ "bool": { "must": conditions } })
    }
}

fn build_sort(sort: &[SearchComparator], tie_breaker: &str) -> Value {
    Value::Array(
        sort.iter()
            .filter_map(|comp| match comp {
                SearchComparator::Field { field, ascending } => {
                    let field = if field.is_text() {
                        format!("{}.keyword", field.field_name())
                    } else {
                        field.field_name().to_string()
                    };

                    Some(json!({
                        field: if *ascending { "asc" } else { "desc" }
                    }))
                }
                _ => None,
            })
            .chain([json!({
                tie_breaker: "asc"
            })])
            .collect(),
    )
}

fn json_serialize(request: &mut String, document: &IndexDocument) {
    request.push('{');
    for (idx, (k, v)) in document.fields.iter().enumerate() {
        if idx > 0 {
            request.push(',');
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
    request.push('}');
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
