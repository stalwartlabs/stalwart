/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::*;
use crate::Server;
use bumpalo::collections::{String as BumpString, Vec as BumpVec};
use mail_auth::{
    IpLookupStrategy,
    dns::{Mx, RecordSet},
};
use std::{
    borrow::Cow,
    cmp::Ordering,
    fmt::{Display, Write},
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
};
use store::{Deserialize, Rows, Value, dispatch::lookup::KeyValue};
use trc::AddContext;

const MAX_DNS_IP_RESULTS: usize = 10;

const STRING_ARGS: [&[usize]; 9] = [
    &[0],
    &[0],
    &[0, 1],
    &[0, 1],
    &[0, 1, 2],
    &[0, 1],
    &[0, 1],
    &[0, 1],
    &[0, 1],
];

pub(crate) struct AsyncCall<'a> {
    pub id: u16,
    pub args: [Variable<'a>; MAX_ASYNC_ARGS],
}

pub(crate) enum AsyncResult {
    Value(Variable<'static>),
    Text(String),
    Ips(Vec<IpAddr>),
    Mx(RecordSet<Mx>),
    Txt(Vec<u8>),
    Ptr(RecordSet<Box<str>>),
    Ipv4(RecordSet<Ipv4Addr>),
    Ipv6(RecordSet<Ipv6Addr>),
    Rows(Rows),
}

#[derive(Debug)]
enum StoredValue {
    Integer(i64),
    Float(f64),
    Text(String),
}

impl<'a> AsyncCall<'a> {
    pub fn new(id: u16, mut args: [Variable<'a>; MAX_ASYNC_ARGS], arena: &'a Bump) -> Self {
        let string_args = STRING_ARGS.get(id as usize).copied().unwrap_or_default();
        for (position, arg) in args.iter_mut().enumerate() {
            if string_args.contains(&position) {
                *arg = Variable::String(arg.to_str(arena));
            }
        }
        if u32::from(id) == F_SQL_QUERY
            && let Some(arg) = args.get_mut(2)
        {
            *arg = sql_argument(*arg, arena);
        }
        AsyncCall { id, args }
    }

    fn str(&self, position: usize) -> &'a str {
        match self.args.get(position) {
            Some(Variable::String(s)) => s,
            _ => "",
        }
    }
}

fn sql_argument<'a>(value: Variable<'a>, arena: &'a Bump) -> Variable<'a> {
    let normalize = |value: Variable<'a>| match value {
        Variable::String(_) | Variable::Integer(_) | Variable::Float(_) => value,
        value => Variable::String(value.to_str(arena)),
    };
    match value {
        Variable::Array(items) => {
            Variable::Array(arena.alloc_slice_fill_iter(items.iter().map(|item| normalize(*item))))
        }
        value => normalize(value),
    }
}

impl Server {
    pub(crate) async fn eval_fnc(
        &self,
        call: AsyncCall<'_>,
        session_id: u64,
    ) -> trc::Result<AsyncResult> {
        match u32::from(call.id) {
            F_IS_LOCAL_DOMAIN => self
                .domain(call.str(0))
                .await
                .caused_by(trc::location!())
                .map(|v| AsyncResult::Value(v.is_some().into())),
            F_IS_LOCAL_ADDRESS => self
                .rcpt_id_from_email(call.str(0))
                .await
                .caused_by(trc::location!())
                .map(|v| AsyncResult::Value(v.is_some().into())),
            F_KEY_GET => {
                let Some(store) = self.get_lookup_store(call.str(0)) else {
                    return Ok(AsyncResult::Value(Variable::default()));
                };
                store
                    .key_get::<StoredValue>(call.str(1))
                    .await
                    .map(|value| match value {
                        Some(StoredValue::Integer(value)) => {
                            AsyncResult::Value(Variable::Integer(value))
                        }
                        Some(StoredValue::Float(value)) => {
                            AsyncResult::Value(Variable::Float(value))
                        }
                        Some(StoredValue::Text(text)) => AsyncResult::Text(text),
                        None => AsyncResult::Value(Variable::default()),
                    })
                    .caused_by(trc::location!())
            }
            F_KEY_EXISTS => {
                let Some(store) = self.get_lookup_store(call.str(0)) else {
                    return Ok(AsyncResult::Value(Variable::default()));
                };
                store
                    .key_exists(call.str(1))
                    .await
                    .caused_by(trc::location!())
                    .map(|v| AsyncResult::Value(v.into()))
            }
            F_KEY_SET => {
                let Some(store) = self.get_lookup_store(call.str(0)) else {
                    return Ok(AsyncResult::Value(Variable::default()));
                };
                store
                    .key_set(KeyValue::new(
                        call.str(1).as_bytes().to_vec(),
                        call.str(2).as_bytes().to_vec(),
                    ))
                    .await
                    .map(|_| AsyncResult::Value(true.into()))
                    .caused_by(trc::location!())
            }
            F_COUNTER_INCR => {
                let Some(store) = self.get_lookup_store(call.str(0)) else {
                    return Ok(AsyncResult::Value(Variable::default()));
                };
                let value = call
                    .args
                    .get(2)
                    .and_then(|v| v.to_integer())
                    .unwrap_or_default();
                store
                    .counter_incr(KeyValue::new(call.str(1).as_bytes().to_vec(), value), true)
                    .await
                    .map(|v| AsyncResult::Value(Variable::Integer(v)))
                    .caused_by(trc::location!())
            }
            F_COUNTER_GET => {
                let Some(store) = self.get_lookup_store(call.str(0)) else {
                    return Ok(AsyncResult::Value(Variable::default()));
                };
                store
                    .counter_get(call.str(1).as_bytes().to_vec())
                    .await
                    .map(|v| AsyncResult::Value(Variable::Integer(v)))
                    .caused_by(trc::location!())
            }
            F_DNS_QUERY => self.dns_query(&call).await,
            F_SQL_QUERY => self.sql_query(&call, session_id).await,
            _ => Ok(AsyncResult::Value(Variable::default())),
        }
    }

    async fn sql_query(&self, call: &AsyncCall<'_>, session_id: u64) -> trc::Result<AsyncResult> {
        let store_name = call.str(0);
        let Some(store) = self
            .get_lookup_store(store_name)
            .and_then(|v| v.into_store())
        else {
            return Err(trc::EventType::Eval(trc::EvalEvent::Error)
                .into_err()
                .id(store_name.to_string())
                .span_id(session_id)
                .details("Store not found or is not a SQL store"));
        };
        let query = call.str(1);

        if query.is_empty() {
            return Err(trc::EventType::Eval(trc::EvalEvent::Error)
                .into_err()
                .details("Empty query string")
                .span_id(session_id));
        }

        let arguments = match call.args.get(2).copied().unwrap_or_default() {
            Variable::Array(l) => l.iter().map(|v| to_store_value(*v)).collect(),
            v => vec![to_store_value(v)],
        };

        if query
            .as_bytes()
            .get(..6)
            .is_some_and(|q| q.eq_ignore_ascii_case(b"SELECT"))
        {
            store
                .sql_query::<Rows>(query, arguments)
                .await
                .map(AsyncResult::Rows)
                .caused_by(trc::location!())
        } else {
            store
                .sql_query::<usize>(query, arguments)
                .await
                .map(|v| AsyncResult::Value(v.into()))
                .caused_by(trc::location!())
        }
    }

    async fn dns_query(&self, call: &AsyncCall<'_>) -> trc::Result<AsyncResult> {
        let entry = call.str(0);
        let record_type = call.str(1);
        let resolver = &self.core.smtp.resolvers.dns;
        let cache = &self.inner.cache;

        hashify::fnc_map_ignore_case!(record_type.as_bytes(),
            "ip" => {
                resolver
                    .ip_lookup(
                        entry,
                        IpLookupStrategy::Ipv4thenIpv6,
                        MAX_DNS_IP_RESULTS,
                        Some(&cache.dns_ipv4),
                        Some(&cache.dns_ipv6),
                    )
                    .await
                    .map(AsyncResult::Ips)
                    .map_err(|err| trc::Error::from(err).caused_by(trc::location!()))
            },
            "mx" => {
                resolver
                    .mx_lookup(entry, Some(&cache.dns_mx))
                    .await
                    .map(AsyncResult::Mx)
                    .map_err(|err| trc::Error::from(err).caused_by(trc::location!()))
            },
            "txt" => {
                resolver
                    .txt_raw_lookup(entry)
                    .await
                    .map(AsyncResult::Txt)
                    .map_err(|err| trc::Error::from(err).caused_by(trc::location!()))
            },
            "ptr" => {
                resolver
                    .ptr_lookup(
                        entry.parse::<IpAddr>().map_err(|err| {
                            trc::EventType::Eval(trc::EvalEvent::Error)
                                .into_err()
                                .details("Failed to parse IP address")
                                .reason(err)
                        })?,
                        Some(&cache.dns_ptr),
                    )
                    .await
                    .map(AsyncResult::Ptr)
                    .map_err(|err| trc::Error::from(err).caused_by(trc::location!()))
            },
            "ipv4" => {
                resolver
                    .ipv4_lookup(entry, Some(&cache.dns_ipv4))
                    .await
                    .map(AsyncResult::Ipv4)
                    .map_err(|err| trc::Error::from(err).caused_by(trc::location!()))
            },
            "ipv6" => {
                resolver
                    .ipv6_lookup(entry, Some(&cache.dns_ipv6))
                    .await
                    .map(AsyncResult::Ipv6)
                    .map_err(|err| trc::Error::from(err).caused_by(trc::location!()))
            },
            _ => Ok(AsyncResult::Value(Variable::default())),
        )
    }
}

impl AsyncResult {
    pub fn into_variable(self, arena: &Bump) -> Variable<'_> {
        match self {
            AsyncResult::Value(value) => value,
            AsyncResult::Text(text) => Variable::String(arena.alloc_str(&text)),
            AsyncResult::Ips(ips) => display_all(arena, ips.iter()),
            AsyncResult::Mx(mx) => {
                let mut items = BumpVec::new_in(arena);
                items.extend(mx.records.iter().flat_map(|mx| {
                    mx.exchanges.iter().map(|host| {
                        Variable::String(arena.alloc_str(host.strip_suffix('.').unwrap_or(host)))
                    })
                }));
                Variable::Array(items.into_bump_slice())
            }
            AsyncResult::Txt(txt) => std::str::from_utf8(&txt)
                .map(|text| Variable::String(arena.alloc_str(text)))
                .unwrap_or_default(),
            AsyncResult::Ptr(ptr) => Variable::Array(
                arena.alloc_slice_fill_iter(
                    ptr.records
                        .iter()
                        .map(|host| Variable::String(arena.alloc_str(host))),
                ),
            ),
            AsyncResult::Ipv4(ips) => display_all(arena, ips.records.iter()),
            AsyncResult::Ipv6(ips) => display_all(arena, ips.records.iter()),
            AsyncResult::Rows(rows) => rows_to_variable(rows, arena),
        }
    }
}

fn display_all<'a, 'i, T: Display + 'i>(
    arena: &'a Bump,
    items: impl ExactSizeIterator<Item = &'i T>,
) -> Variable<'a> {
    Variable::Array(arena.alloc_slice_fill_iter(items.map(|item| {
        let mut out = BumpString::new_in(arena);
        let _ = write!(out, "{item}");
        Variable::String(out.into_bump_str())
    })))
}

fn rows_to_variable(mut rows: Rows, arena: &Bump) -> Variable<'_> {
    match rows.rows.len().cmp(&1) {
        Ordering::Equal => {
            let mut row = rows.rows.pop().map(|row| row.values).unwrap_or_default();
            match row.len().cmp(&1) {
                Ordering::Equal if !matches!(row.first(), Some(Value::Null)) => row
                    .pop()
                    .map(|value| into_variable(value, arena))
                    .unwrap_or_default(),
                Ordering::Less => Variable::default(),
                _ => Variable::Array(
                    arena.alloc_slice_fill_iter(row.into_iter().map(|v| into_variable(v, arena))),
                ),
            }
        }
        Ordering::Less => Variable::default(),
        Ordering::Greater => {
            Variable::Array(
                arena.alloc_slice_fill_iter(rows.rows.into_iter().map(|row| {
                    Variable::Array(arena.alloc_slice_fill_iter(
                        row.values.into_iter().map(|v| into_variable(v, arena)),
                    ))
                })),
            )
        }
    }
}

impl Deserialize for StoredValue {
    fn deserialize(bytes: &[u8]) -> trc::Result<Self> {
        Ok(StoredValue::Text(
            String::from_utf8_lossy(bytes).into_owned(),
        ))
    }
}

impl From<Value<'static>> for StoredValue {
    fn from(value: Value<'static>) -> Self {
        match value {
            Value::Integer(v) => StoredValue::Integer(v),
            Value::Bool(v) => StoredValue::Integer(i64::from(v)),
            Value::Float(v) => StoredValue::Float(v),
            Value::Text(v) => StoredValue::Text(v.into_owned()),
            Value::Blob(v) => StoredValue::Text(String::from_utf8_lossy(&v).into_owned()),
            Value::Null => StoredValue::Text(String::new()),
        }
    }
}

fn to_store_value(value: Variable<'_>) -> Value<'_> {
    match value {
        Variable::String(v) => Value::Text(Cow::Borrowed(v)),
        Variable::Integer(v) => Value::Integer(v),
        Variable::Float(v) => Value::Float(v),
        _ => Value::Null,
    }
}

fn into_variable<'a>(value: Value<'_>, arena: &'a Bump) -> Variable<'a> {
    match value {
        Value::Integer(v) => Variable::Integer(v),
        Value::Bool(v) => Variable::Integer(i64::from(v)),
        Value::Float(v) => Variable::Float(v),
        Value::Text(v) => Variable::String(arena.alloc_str(&v)),
        Value::Blob(v) => match String::from_utf8_lossy(&v) {
            Cow::Borrowed(text) => Variable::String(arena.alloc_str(text)),
            Cow::Owned(text) => Variable::String(arena.alloc_str(&text)),
        },
        Value::Null => Variable::default(),
    }
}
