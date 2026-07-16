/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    backend::postgres::{PostgresStore, PsqlSearchField, into_error, into_pool_error},
    search::{
        IndexDocument, KeyValueMatch, SearchFilter, SearchQuery, SearchResults, SearchValue,
        TextMatch,
    },
    write::SearchIndex,
};
use nlp::language::Language;
use std::{cmp::Ordering, fmt::Write};
use tokio_postgres::{
    IsolationLevel,
    types::{FromSql, ToSql, Type, WrongType},
};

impl PostgresStore {
    pub async fn index(&self, documents: Vec<IndexDocument>) -> trc::Result<()> {
        let mut conn = self.conn_pool.get().await.map_err(into_pool_error)?;
        let trx = conn
            .build_transaction()
            .isolation_level(IsolationLevel::ReadCommitted)
            .start()
            .await
            .map_err(into_error)?;

        for document in documents {
            let index = document.index;
            let primary_keys = index.primary_keys();
            let all_fields = index.all_fields();
            let fields = document.fields;
            let mut values = Vec::with_capacity(fields.len() + 2);
            let mut query = format!("INSERT INTO {} (", index.psql_table());

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

                if let Some(value) = fields.get(field) {
                    let value_ref = format!("${}", values.len() + 1);
                    let (text_len, language) = if let SearchValue::Text { value, language } = value
                    {
                        (value.len(), pg_lang(language).unwrap_or("simple"))
                    } else {
                        (0, "simple")
                    };

                    if field.is_text() {
                        let _ = write!(&mut query, "to_tsvector('{language}',{value_ref})");
                    } else if text_len > 512 {
                        query.push_str("left(");
                        query.push_str(&value_ref);
                        query.push_str(",512)");
                    } else {
                        query.push_str(&value_ref);
                    }

                    values.push(value as &(dyn ToSql + Sync));
                } else {
                    query.push_str("NULL");
                }
            }

            query.push_str(") ON CONFLICT (");
            for (i, pkey) in primary_keys.iter().enumerate() {
                if i > 0 {
                    query.push(',');
                }
                query.push_str(pkey.column());
            }
            query.push_str(") DO UPDATE SET ");
            for (i, field) in all_fields.iter().enumerate() {
                if i > 0 {
                    query.push(',');
                }
                let column = field.column();
                let _ = write!(&mut query, "{column} = EXCLUDED.{column}");
            }

            trx.execute(&query, &values).await.map_err(into_error)?;
        }

        trx.commit().await.map_err(into_error)
    }

    pub async fn query<R: SearchResults>(
        &self,
        index: SearchIndex,
        filters: &[SearchFilter],
    ) -> trc::Result<R> {
        let mut query = format!("SELECT {} FROM {}", R::field().column(), index.psql_table());
        let params = self.build_filter(&mut query, filters);
        let conn = self.conn_pool.get().await.map_err(into_pool_error)?;
        let s = conn.prepare_cached(&query).await.map_err(into_error)?;

        conn.query(&s, params.as_slice())
            .await
            .and_then(|rows| {
                let mut results = R::default();
                for row in rows {
                    results.insert(row.try_get::<_, DocId>(0)?.0);
                }
                Ok(results)
            })
            .map_err(into_error)
    }

    pub async fn unindex(&self, filter: SearchQuery) -> trc::Result<u64> {
        debug_assert!(!filter.filters.is_empty());
        let mut query = format!("DELETE FROM {} ", filter.index.psql_table());
        let params = self.build_filter(&mut query, &filter.filters);
        let conn = self.conn_pool.get().await.map_err(into_pool_error)?;
        let s = conn.prepare_cached(&query).await.map_err(into_error)?;

        conn.execute(&s, params.as_slice())
            .await
            .map_err(into_error)
    }

    fn build_filter<'x>(
        &self,
        query: &mut String,
        filters: &'x [SearchFilter],
    ) -> Vec<&'x (dyn ToSql + Sync)> {
        if filters.is_empty() {
            return Vec::new();
        }
        query.push_str(" WHERE ");
        let mut operator_stack = Vec::new();
        let mut operator = &SearchFilter::And;
        let mut is_first = true;
        let mut values = Vec::new();

        for filter in filters {
            match filter {
                SearchFilter::Text {
                    field,
                    op,
                    value,
                    language,
                } => {
                    if !is_first {
                        match operator {
                            SearchFilter::And => query.push_str(" AND "),
                            SearchFilter::Or => query.push_str(" OR "),
                            _ => (),
                        }
                    } else {
                        is_first = false;
                    }
                    let value_pos = values.len() + 1;
                    query.push_str(field.column());
                    if field.is_text() {
                        query.push(' ');
                        let language = pg_lang(language).unwrap_or("simple");
                        match op {
                            TextMatch::Keyword => {
                                let _ =
                                    write!(query, "@@ plainto_tsquery('{language}', ${value_pos})");
                            }
                            TextMatch::Phrase => {
                                let _ = write!(
                                    query,
                                    "@@ phraseto_tsquery('{language}', ${value_pos})"
                                );
                            }
                            TextMatch::Prefix => {
                                let _ = write!(
                                    query,
                                    "@@ to_tsquery('simple', coalesce(nullif(array_to_string(tsvector_to_array(to_tsvector('simple', ${value_pos})), ':* & '), '') || ':*', ''))"
                                );
                            }
                        }
                    } else {
                        match op {
                            TextMatch::Prefix => {
                                let _ = write!(query, " LIKE ${value_pos} || '%'");
                            }
                            _ => {
                                let _ = write!(query, " = ${value_pos}");
                            }
                        }
                    }
                    values.push(value as &(dyn ToSql + Sync));
                }
                SearchFilter::KeyValue { field, key, op } => {
                    if !is_first {
                        match operator {
                            SearchFilter::And => query.push_str(" AND "),
                            SearchFilter::Or => query.push_str(" OR "),
                            _ => (),
                        }
                    } else {
                        is_first = false;
                    }
                    query.push_str(field.column());
                    query.push(' ');
                    let key_pos = values.len() + 1;
                    values.push(key as &(dyn ToSql + Sync));
                    match op {
                        KeyValueMatch::Equals(value) => {
                            let value_pos = values.len() + 1;
                            let _ = write!(query, "->> ${key_pos} = ${value_pos}");
                            values.push(value as &(dyn ToSql + Sync));
                        }
                        KeyValueMatch::Contains(value) => {
                            let value_pos = values.len() + 1;
                            let _ = write!(query, "->> ${key_pos} LIKE '%' || ${value_pos} || '%'");
                            values.push(value as &(dyn ToSql + Sync));
                        }
                        KeyValueMatch::Exists => {
                            let _ = write!(query, " ? ${key_pos}");
                        }
                    }
                }
                SearchFilter::Integer { field, op, value } => {
                    if !is_first {
                        match operator {
                            SearchFilter::And => query.push_str(" AND "),
                            SearchFilter::Or => query.push_str(" OR "),
                            _ => (),
                        }
                    } else {
                        is_first = false;
                    }
                    let cmp = match op {
                        Ordering::Less => "<",
                        Ordering::Equal => "=",
                        Ordering::Greater => ">",
                    };
                    let _ = write!(query, "{} {cmp} {value}", field.column());
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
}

impl ToSql for SearchValue {
    fn to_sql(
        &self,
        ty: &tokio_postgres::types::Type,
        out: &mut bytes::BytesMut,
    ) -> Result<tokio_postgres::types::IsNull, Box<dyn std::error::Error + Sync + Send>>
    where
        Self: Sized,
    {
        match self {
            SearchValue::Text { value, .. } => {
                // Truncate large text fields to avoid Postgres errors (see https://www.postgresql.org/docs/current/textsearch-limitations.html)

                if value.len() > 650_000 {
                    (&value[..value.floor_char_boundary(650_000)]).to_sql(ty, out)
                } else {
                    value.to_sql(ty, out)
                }
            }
            SearchValue::Int(v) => match *ty {
                Type::INT4 => (*v as i32).to_sql(ty, out),
                _ => v.to_sql(ty, out),
            },
            SearchValue::Uint(v) => match *ty {
                Type::INT4 => (*v as i32).to_sql(ty, out),
                _ => (*v as i64).to_sql(ty, out),
            },
            SearchValue::Boolean(v) => v.to_sql(ty, out),
            SearchValue::KeyValues(kv) => {
                serde_json::to_value(kv).unwrap_or_default().to_sql(ty, out)
            }
        }
    }

    fn accepts(_: &tokio_postgres::types::Type) -> bool
    where
        Self: Sized,
    {
        true
    }

    fn to_sql_checked(
        &self,
        ty: &tokio_postgres::types::Type,
        out: &mut bytes::BytesMut,
    ) -> Result<tokio_postgres::types::IsNull, Box<dyn std::error::Error + Sync + Send>> {
        match self {
            SearchValue::Text { value, .. } => {
                // Truncate large text fields to avoid Postgres errors (see https://www.postgresql.org/docs/current/textsearch-limitations.html)

                if value.len() > 650_000 {
                    (&value[..value.floor_char_boundary(650_000)]).to_sql_checked(ty, out)
                } else {
                    value.to_sql_checked(ty, out)
                }
            }
            SearchValue::Int(v) => match *ty {
                Type::INT4 => (*v as i32).to_sql_checked(ty, out),
                _ => v.to_sql_checked(ty, out),
            },
            SearchValue::Uint(v) => match *ty {
                Type::INT4 => (*v as i32).to_sql_checked(ty, out),
                _ => (*v as i64).to_sql_checked(ty, out),
            },
            SearchValue::Boolean(v) => v.to_sql_checked(ty, out),
            SearchValue::KeyValues(kv) => serde_json::to_value(kv)
                .unwrap_or_default()
                .to_sql_checked(ty, out),
        }
    }
}

struct DocId(u64);

impl FromSql<'_> for DocId {
    fn from_sql(
        ty: &tokio_postgres::types::Type,
        raw: &'_ [u8],
    ) -> Result<Self, Box<dyn std::error::Error + Sync + Send>> {
        match ty {
            &Type::INT4 => i32::from_sql(ty, raw).map(|v| DocId(v as u64)),
            &Type::INT8 | &Type::OID => i64::from_sql(ty, raw).map(|v| DocId(v as u64)),
            _ => Err(Box::new(WrongType::new::<DocId>(ty.clone()))),
        }
    }

    fn accepts(typ: &Type) -> bool {
        matches!(typ, &Type::INT4 | &Type::INT8 | &Type::OID)
    }
}

#[inline(always)]
fn pg_lang(lang: &Language) -> Option<&'static str> {
    match lang {
        Language::Esperanto => None,
        Language::English => Some("english"),
        Language::Russian => Some("russian"),
        Language::Mandarin => None,
        Language::Spanish => Some("spanish"),
        Language::Portuguese => Some("portuguese"),
        Language::Italian => Some("italian"),
        Language::Bengali => None,
        Language::French => Some("french"),
        Language::German => Some("german"),
        Language::Ukrainian => None,
        Language::Georgian => None,
        Language::Arabic => Some("arabic"),
        Language::Hindi => Some("hindi"),
        Language::Japanese => None,
        Language::Hebrew => None,
        Language::Yiddish => Some("yiddish"),
        Language::Polish => None,
        Language::Amharic => None,
        Language::Javanese => None,
        Language::Korean => None,
        Language::Bokmal => Some("norwegian"), // Norwegian covers Bokmål
        Language::Danish => Some("danish"),
        Language::Swedish => Some("swedish"),
        Language::Finnish => Some("finnish"),
        Language::Turkish => Some("turkish"),
        Language::Dutch => Some("dutch"),
        Language::Hungarian => Some("hungarian"),
        Language::Czech => None,
        Language::Greek => Some("greek"),
        Language::Bulgarian => None,
        Language::Belarusian => None,
        Language::Marathi => None,
        Language::Kannada => None,
        Language::Romanian => Some("romanian"),
        Language::Slovene => None,
        Language::Croatian => None,
        Language::Serbian => Some("serbian"),
        Language::Macedonian => None,
        Language::Lithuanian => Some("lithuanian"),
        Language::Latvian => None,
        Language::Estonian => None,
        Language::Tamil => Some("tamil"),
        Language::Vietnamese => None,
        Language::Urdu => None,
        Language::Thai => None,
        Language::Gujarati => None,
        Language::Uzbek => None,
        Language::Punjabi => None,
        Language::Azerbaijani => None,
        Language::Indonesian => Some("indonesian"),
        Language::Telugu => None,
        Language::Persian => None,
        Language::Malayalam => None,
        Language::Oriya => None,
        Language::Burmese => None,
        Language::Nepali => Some("nepali"),
        Language::Sinhalese => None,
        Language::Khmer => None,
        Language::Turkmen => None,
        Language::Akan => None,
        Language::Zulu => None,
        Language::Shona => None,
        Language::Afrikaans => None,
        Language::Latin => None,
        Language::Slovak => None,
        Language::Catalan => Some("catalan"),
        Language::Tagalog => None,
        Language::Armenian => Some("armenian"),
        Language::Unknown | Language::None => None,
    }
}
