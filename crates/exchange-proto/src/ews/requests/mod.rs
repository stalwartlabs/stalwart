/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

pub mod attachment;
pub mod availability;
pub mod bulk;
pub mod config;
pub mod conversation;
pub mod delegate;
pub mod dispatch;
pub mod find;
pub mod folder;
pub mod item;
pub mod mailtips;
pub mod notification;
pub mod oof;
pub mod people;
pub mod reminder;
pub mod resolve;
pub mod rules;
pub mod search;
pub mod sync;
pub mod target;

mod prelude;

pub use dispatch::EwsRequest;
pub use target::RequestTarget;

use crate::{
    ews::{
        parser::{ParseErrorKind, Parser, Result},
        schema::NameEnum,
        types::value::{EwsValue, parse_bounded},
    },
    xml::{Attrs, Ns},
};
use std::borrow::Cow;

const MAX_SYNC_CHANGES: u16 = 512;
const MAX_CONNECTION_TIMEOUT_MINUTES: u8 = 30;
pub const MAX_REMINDER_ITEMS: u16 = 200;

pub trait AttrValue<'a>: Sized {
    fn parse_attr(p: &Parser<'a>, attrs: &Attrs<'a>, name: &'static str) -> Result<Option<Self>>;
}

impl<'a, E: NameEnum> AttrValue<'a> for E {
    fn parse_attr(p: &Parser<'a>, attrs: &Attrs<'a>, name: &'static str) -> Result<Option<Self>> {
        p.attr_enum(attrs, name, E::parse_name)
    }
}

macro_rules! xml_attr_value {
    ($($ty:ty),+) => {
        $(impl<'a> AttrValue<'a> for $ty {
            fn parse_attr(p: &Parser<'a>, attrs: &Attrs<'a>, name: &'static str) -> Result<Option<Self>> {
                p.attr_value(attrs, name)
            }
        })+
    };
}

xml_attr_value!(bool, i32, u32, Cow<'a, str>);

pub fn non_empty<T>(p: &Parser<'_>, list: Option<Vec<T>>, name: &'static str) -> Result<Vec<T>> {
    match list {
        Some(list) if !list.is_empty() => Ok(list),
        _ => Err(p.error(ParseErrorKind::MissingElement(name))),
    }
}

pub fn optional_non_empty<T>(
    p: &Parser<'_>,
    list: Option<Vec<T>>,
    name: &'static str,
) -> Result<Option<Vec<T>>> {
    match list {
        Some(list) if list.is_empty() => Err(p.error(ParseErrorKind::MissingElement(name))),
        list => Ok(list),
    }
}

pub fn repeated<'a, V: EwsValue<'a>>(
    p: &mut Parser<'a>,
    ns: Ns,
    item: &'static str,
) -> Result<Vec<V>> {
    let mut list = Vec::new();
    while let Some(child) = p.child()? {
        if child.local == item {
            p.expect_ns(&child, ns)?;
            p.count_id()?;
            list.push(V::parse(p, &child.attrs)?);
        } else {
            p.skip()?;
        }
    }
    Ok(list)
}

pub fn parse_max_changes(p: &mut Parser<'_>) -> Result<u16> {
    parse_bounded(p, "MaxChangesReturned", 1, MAX_SYNC_CHANGES)
}

pub fn parse_max_items(p: &mut Parser<'_>) -> Result<u16> {
    parse_bounded(p, "MaxItems", 0, MAX_REMINDER_ITEMS)
}

pub fn parse_connection_timeout(p: &mut Parser<'_>) -> Result<u8> {
    let minutes: i64 = p.value("ConnectionTimeout")?;
    if minutes < 1 {
        return Err(p.error(ParseErrorKind::InvalidValue("ConnectionTimeout")));
    }
    Ok(u8::try_from(minutes)
        .unwrap_or(u8::MAX)
        .min(MAX_CONNECTION_TIMEOUT_MINUTES))
}

macro_rules! ews_request {
    ($(#[$meta:meta])* pub struct $name:ident<$lt:lifetime> {
        $($field:ident : $kind:ident $ns:ident $el:literal => $ty:ty = |$p:ident, $a:pat_param| $parse:expr),* $(,)?
    }
    $(choice { $($cfield:ident : $ckind:ident $cty:ty),+ $(,)? })?
    $(attrs { $($afield:ident : $akind:ident $attr:literal => $aty:ty $(= $default:expr)?),+ $(,)? })?
    ) => {
        $(#[$meta])*
        #[derive(Debug, Clone, PartialEq)]
        pub struct $name<$lt> {
            $(pub $field: $crate::ews::requests::ews_request!(@ty $kind $ty),)*
            $($(pub $cfield: $crate::ews::requests::ews_request!(@ty $ckind $cty),)+)?
            $($(pub $afield: $crate::ews::requests::ews_request!(@ty $akind $aty),)+)?
        }

        impl<$lt> $name<$lt> {
            pub fn parse(
                p: &mut $crate::ews::parser::Parser<$lt>,
                attrs: &$crate::xml::Attrs<$lt>,
            ) -> $crate::ews::parser::Result<Self> {
                let _ = attrs;
                $($(let $afield = <$aty as $crate::ews::requests::AttrValue>::parse_attr(p, attrs, $attr)?;)+)?
                $(let mut $field: Option<$ty> = None;)*
                $($(let mut $cfield: Option<$cty> = None;)+)?
                while let Some(child) = p.child()? {
                    $($(if let Some(value) = <$cty>::parse_child(p, &child)? {
                        $cfield = Some(value);
                        continue;
                    })+)?
                    $crate::ews::requests::ews_request!(@dispatch p child
                        [$($field $ns $el |$p, $a| $parse;)*]);
                }
                Ok($name {
                    $($field: $crate::ews::requests::ews_request!(@finish p $kind $field $el),)*
                    $($($cfield: $crate::ews::requests::ews_request!(@finish p $ckind $cfield stringify!($cty)),)+)?
                    $($($afield: $crate::ews::requests::ews_request!(@attr p $akind $afield $attr $($default)?),)+)?
                })
            }
        }
    };
    ($(#[$meta:meta])* pub struct $name:ident {
        $($field:ident : $kind:ident $ns:ident $el:literal => $ty:ty = |$p:ident, $a:pat_param| $parse:expr),* $(,)?
    }) => {
        $(#[$meta])*
        #[derive(Debug, Clone, PartialEq)]
        pub struct $name {
            $(pub $field: $crate::ews::requests::ews_request!(@ty $kind $ty),)*
        }

        impl $name {
            pub fn parse<'x>(
                p: &mut $crate::ews::parser::Parser<'x>,
                _: &$crate::xml::Attrs<'x>,
            ) -> $crate::ews::parser::Result<Self> {
                $(let mut $field: Option<$ty> = None;)*
                while let Some(child) = p.child()? {
                    $crate::ews::requests::ews_request!(@dispatch p child
                        [$($field $ns $el |$p, $a| $parse;)*]);
                }
                Ok($name {
                    $($field: $crate::ews::requests::ews_request!(@finish p $kind $field $el),)*
                })
            }
        }
    };
    (@ty req $ty:ty) => { $ty };
    (@ty list $ty:ty) => { $ty };
    (@ty def $ty:ty) => { $ty };
    (@ty opt $ty:ty) => { Option<$ty> };
    (@ty olist $ty:ty) => { Option<$ty> };
    (@ty nonempty $ty:ty) => { Option<$ty> };
    (@finish $p:ident req $f:ident $el:expr) => {
        $crate::ews::types::recurrence::required($p, $f, $el)?
    };
    (@finish $p:ident list $f:ident $el:expr) => {
        $crate::ews::requests::non_empty($p, $f, $el)?
    };
    (@finish $p:ident opt $f:ident $el:expr) => { $f };
    (@finish $p:ident nonempty $f:ident $el:expr) => {
        $f.filter(|list| !list.is_empty())
    };
    (@finish $p:ident olist $f:ident $el:expr) => {
        $crate::ews::requests::optional_non_empty($p, $f, $el)?
    };
    (@attr $p:ident req $f:ident $attr:literal) => {
        $f.ok_or_else(|| $p.error($crate::ews::parser::ParseErrorKind::MissingAttribute($attr)))?
    };
    (@attr $p:ident opt $f:ident $attr:literal) => { $f };
    (@attr $p:ident def $f:ident $attr:literal $default:expr) => { $f.unwrap_or($default) };
    (@dispatch $pp:ident $child:ident []) => { $pp.skip()? };
    (@dispatch $pp:ident $child:ident [$($field:ident $ns:ident $el:literal |$p:ident, $a:pat_param| $parse:expr;)+]) => {
        hashify::fnc_map!($child.local.as_bytes(),
            $($el => {
                $pp.expect_ns(&$child, $crate::ews::requests::ews_request!(@ns $ns))?;
                $field = Some({
                    let $p = &mut *$pp;
                    let $a = &$child.attrs;
                    $parse
                });
            },)+
            _ => {
                $pp.skip()?;
            }
        )
    };
    (@ns M) => { $crate::xml::Ns::Messages };
    (@ns T) => { $crate::xml::Ns::Types };
}

pub(crate) use ews_request;
