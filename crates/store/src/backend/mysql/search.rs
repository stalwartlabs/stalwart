/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    backend::{
        MAX_TOKEN_LENGTH,
        mysql::{MysqlSearchField, MysqlStore, into_error},
    },
    search::{
        IndexDocument, SearchComparator, SearchDocumentId, SearchFilter, SearchOperator,
        SearchQuery, SearchValue,
    },
    write::SearchIndex,
};
use mysql_async::{IsolationLevel, TxOpts, Value, prelude::Queryable};
use nlp::tokenizers::word::WordTokenizer;
use std::fmt::Write;

impl MysqlStore {
    pub async fn index(&self, documents: Vec<IndexDocument>) -> trc::Result<()> {
        let mut conn = self.conn_pool.get_conn().await.map_err(into_error)?;
        let mut tx_opts = TxOpts::default();
        tx_opts
            .with_consistent_snapshot(false)
            .with_isolation_level(IsolationLevel::ReadCommitted);
        let mut trx = conn.start_transaction(tx_opts).await.map_err(into_error)?;

        for document in documents {
            let index = document.index;
            let primary_keys = index.primary_keys();
            let all_fields = index.all_fields();
            let mut fields = document.fields;
            let mut values = Vec::with_capacity(fields.len() + 2);
            let mut query = format!("INSERT INTO {} (", index.mysql_table());

            for (i, field) in primary_keys.iter().chain(all_fields).enumerate() {
                if i > 0 {
                    query.push(',');
                }
                query.push_str(field.column());
            }

            query.push_str(") VALUES (");

            for (i, field) in primary_keys.iter().chain(all_fields).enumerate() {
                if i > 0 {
                    query.push(',');
                }

                if let Some(value) = fields.remove(field) {
                    query.push('?');
                    values.push(value);
                } else {
                    query.push_str("NULL");
                }
            }

            query.push_str(") ON DUPLICATE KEY UPDATE ");
            for (i, field) in all_fields.iter().enumerate() {
                if i > 0 {
                    query.push(',');
                }
                let column = field.column();
                let _ = write!(&mut query, "{column} = VALUES({column})");
            }

            let s = trx.prep(&query).await.map_err(into_error)?;

            trx.exec_drop(&s, values).await.map_err(into_error)?;
        }

        trx.commit().await.map_err(into_error)
    }

    pub async fn query<R: SearchDocumentId>(
        &self,
        index: SearchIndex,
        filters: &[SearchFilter],
        sort: &[SearchComparator],
    ) -> trc::Result<Vec<R>> {
        let mut query = format!(
            "SELECT {} FROM {}",
            R::field().column(),
            index.mysql_table()
        );
        let params = build_filter(&mut query, filters);
        if !sort.is_empty() {
            build_sort(&mut query, sort);
        }

        let mut conn = self.conn_pool.get_conn().await.map_err(into_error)?;
        let s = conn.prep(query).await.map_err(into_error)?;

        conn.exec::<i64, _, _>(s, params)
            .await
            .map(|r| r.into_iter().map(|r| R::from_u64(r as u64)).collect())
            .map_err(into_error)
    }

    pub async fn unindex(&self, filter: SearchQuery) -> trc::Result<u64> {
        let mut query = format!("DELETE FROM {} ", filter.index.mysql_table());
        let params = build_filter(&mut query, &filter.filters);

        let mut conn = self.conn_pool.get_conn().await.map_err(into_error)?;
        let s = conn.prep(query).await.map_err(into_error)?;

        conn.exec_drop(s, params)
            .await
            .map(|_| conn.affected_rows() as u64)
            .map_err(into_error)
    }
}

fn build_filter(query: &mut String, filters: &[SearchFilter]) -> Vec<Value> {
    if filters.is_empty() {
        return Vec::new();
    }
    query.push_str(" WHERE ");
    let mut operator_stack = Vec::new();
    let mut operator = &SearchFilter::And;
    let mut is_first = true;
    let mut values: Vec<Value> = Vec::new();

    for filter in filters {
        match filter {
            SearchFilter::Operator { field, op, value } => {
                if !is_first {
                    match operator {
                        SearchFilter::And => query.push_str(" AND "),
                        SearchFilter::Or => query.push_str(" OR "),
                        _ => (),
                    }
                } else {
                    is_first = false;
                }

                if field.is_text() && matches!(op, SearchOperator::Equal | SearchOperator::Contains)
                {
                    let (value, mode) = match (value, op) {
                        (SearchValue::Text { value, .. }, SearchOperator::Equal) => {
                            (Value::Bytes(format!("{value:?}").into_bytes()), "BOOLEAN")
                        }
                        (SearchValue::Text { value, .. }, ..) => {
                            let mut text_query = String::with_capacity(value.len() + 1);

                            for item in WordTokenizer::new(value, MAX_TOKEN_LENGTH) {
                                if !text_query.is_empty() {
                                    text_query.push(' ');
                                }
                                text_query.push('+');
                                text_query.push_str(&item.word);
                            }

                            (Value::Bytes(text_query.into_bytes()), "BOOLEAN")
                        }
                        _ => {
                            debug_assert!(false, "Invalid search value for text field");
                            continue;
                        }
                    };
                    let _ = write!(query, "MATCH({}) AGAINST(? IN {mode} MODE)", field.column());
                    values.push(value);
                } else if let SearchValue::KeyValues(kv) = value {
                    let (key, value) = kv.iter().next().unwrap();

                    values.push(Value::Bytes(format!("$.{key:?}").into_bytes()));

                    if !value.is_empty() {
                        if op == &SearchOperator::Equal {
                            let _ = write!(query, "JSON_EXTRACT({}, ?) = ?", field.column());
                            values.push(Value::Bytes(value.as_bytes().to_vec()));
                        } else {
                            let _ = write!(query, "JSON_EXTRACT({}, ?) LIKE ?", field.column(),);
                            values.push(Value::Bytes(format!("%{value}%").into_bytes()));
                        }
                    } else {
                        let _ = write!(query, "JSON_CONTAINS_PATH({}, 'one', ?)", field.column(),);
                    }
                } else {
                    query.push_str(field.column());
                    query.push(' ');
                    op.write_mysql(query);
                    values.push(to_mysql(value));
                }
            }
            SearchFilter::And | SearchFilter::Or => {
                if !is_first {
                    match operator {
                        SearchFilter::And => query.push_str(" AND "),
                        SearchFilter::Or => query.push_str(" OR "),
                        _ => (),
                    }
                } else {
                    is_first = false;
                }

                operator_stack.push((operator, is_first));
                operator = filter;
                is_first = true;
                query.push('(');
            }
            SearchFilter::Not => {
                if !is_first {
                    match operator {
                        SearchFilter::And => query.push_str(" AND "),
                        SearchFilter::Or => query.push_str(" OR "),
                        _ => (),
                    }
                } else {
                    is_first = false;
                }

                operator_stack.push((operator, is_first));
                operator = &SearchFilter::And;
                is_first = true;
                query.push_str("NOT (");
            }
            SearchFilter::End => {
                let p = operator_stack.pop().unwrap_or((&SearchFilter::And, true));
                operator = p.0;
                is_first = p.1;
                query.push(')');
            }
            SearchFilter::DocumentSet(_) => {
                debug_assert!(
                    false,
                    "DocumentSet filters are not supported in Postgres backend"
                )
            }
        }
    }

    values
}

fn build_sort(query: &mut String, sort: &[SearchComparator]) {
    query.push_str(" ORDER BY ");
    for (i, comparator) in sort.iter().enumerate() {
        if i > 0 {
            query.push_str(", ");
        }
        match comparator {
            SearchComparator::Field { field, ascending } => {
                query.push_str(field.column());
                if *ascending {
                    query.push_str(" ASC");
                } else {
                    query.push_str(" DESC");
                }
            }
            SearchComparator::DocumentSet { .. } | SearchComparator::SortedSet { .. } => {
                debug_assert!(
                    false,
                    "DocumentSet and SortedSet comparators are not supported "
                );
            }
        }
    }
}

impl SearchOperator {
    fn write_mysql(&self, query: &mut String) {
        match self {
            SearchOperator::LowerThan => {
                let _ = write!(query, "< ?");
            }
            SearchOperator::LowerEqualThan => {
                let _ = write!(query, "<= ?");
            }
            SearchOperator::GreaterThan => {
                let _ = write!(query, "> ?");
            }
            SearchOperator::GreaterEqualThan => {
                let _ = write!(query, ">= ?");
            }
            SearchOperator::Equal => {
                let _ = write!(query, "= ?");
            }
            SearchOperator::Contains => {
                let _ = write!(query, "LIKE '%' CONCAT('%', ?, '%')");
            }
        }
    }
}

impl From<SearchValue> for Value {
    fn from(value: SearchValue) -> Self {
        match value {
            SearchValue::Text { mut value, .. } => {
                // Truncate values larger than 16MB to avoid MySQL errors
                if value.len() > 16_777_214 {
                    let pos = value.floor_char_boundary(16_777_214);
                    value.truncate(pos);
                }

                Value::Bytes(value.into_bytes())
            }
            SearchValue::KeyValues(vec_map) => serde_json::to_string(&vec_map)
                .map(|v| Value::Bytes(v.into_bytes()))
                .unwrap_or(Value::NULL),
            SearchValue::Int(i) => Value::Int(i),
            SearchValue::Uint(i) => Value::Int(i as i64),
            SearchValue::Boolean(b) => Value::Int(b as i64),
        }
    }
}

fn to_mysql(value: &SearchValue) -> Value {
    match value {
        SearchValue::Text { value, .. } => Value::Bytes(value.as_bytes().to_vec()),
        SearchValue::KeyValues(vec_map) => serde_json::to_string(&vec_map)
            .map(|v| Value::Bytes(v.into_bytes()))
            .unwrap_or(Value::NULL),
        SearchValue::Int(i) => Value::Int(*i),
        SearchValue::Uint(i) => Value::Int(*i as i64),
        SearchValue::Boolean(b) => Value::Int(*b as i64),
    }
}
