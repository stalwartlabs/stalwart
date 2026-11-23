/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    common::{
        Base64Text, Braces, Guid, HexCase, LocalDateTime, Precision, UtcSeconds, XsDateTime,
        XsDuration, XsForm, XsZone,
    },
    ews::parser::{Child, ParseErrorKind, Parser, Result},
    xml::{
        Attrs, XmlWriter,
        value::{XsDate, XsTime},
    },
};
use std::borrow::Cow;

const SECONDS_PER_DAY: i64 = 86_400;

pub const T: &str = "t";
pub const M: &str = "m";
pub const XSI: &str = "xsi";

pub trait EwsValue<'x>: Sized {
    fn parse(p: &mut Parser<'x>, attrs: &Attrs<'x>) -> Result<Self>;

    fn merge(slot: &mut Option<Self>, p: &mut Parser<'x>, attrs: &Attrs<'x>) -> Result<()> {
        *slot = Some(Self::parse(p, attrs)?);
        Ok(())
    }

    fn write(&self, w: &mut XmlWriter<'_>, local: &str);
}

impl<'x> EwsValue<'x> for Cow<'x, str> {
    fn parse(p: &mut Parser<'x>, _: &Attrs<'x>) -> Result<Self> {
        p.text()
    }

    fn write(&self, w: &mut XmlWriter<'_>, local: &str) {
        w.leaf(T, local, self);
    }
}

impl<'x> EwsValue<'x> for bool {
    fn parse(p: &mut Parser<'x>, _: &Attrs<'x>) -> Result<Self> {
        p.value("boolean")
    }

    fn write(&self, w: &mut XmlWriter<'_>, local: &str) {
        w.leaf_bool(T, local, *self);
    }
}

macro_rules! int_ews_value {
    ($($ty:ty),+) => {
        $(impl<'x> EwsValue<'x> for $ty {
            fn parse(p: &mut Parser<'x>, _: &Attrs<'x>) -> Result<Self> {
                p.value("integer")
            }

            fn write(&self, w: &mut XmlWriter<'_>, local: &str) {
                w.leaf_i64(T, local, i64::from(*self));
            }
        })+
    };
}

int_ews_value!(i16, i32, i64, u8, u16, u32);

impl<'x> EwsValue<'x> for f64 {
    fn parse(p: &mut Parser<'x>, _: &Attrs<'x>) -> Result<Self> {
        p.value("double")
    }

    fn write(&self, w: &mut XmlWriter<'_>, local: &str) {
        w.start(T, local);
        write_f64(w, *self);
        w.end(T, local);
    }
}

pub fn write_f64(w: &mut XmlWriter<'_>, value: f64) {
    use std::fmt::Write;
    if value.is_nan() {
        w.raw(b"NaN");
    } else if value.is_infinite() {
        w.raw(if value > 0.0 { b"INF" } else { b"-INF" });
    } else {
        let _ = write!(w, "{value}");
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DateTime {
    Utc { seconds: UtcSeconds, millis: u16 },
    Parsed(XsDateTime),
}

impl DateTime {
    pub const fn utc(seconds: UtcSeconds) -> Self {
        DateTime::Utc { seconds, millis: 0 }
    }

    pub fn to_utc(&self) -> Option<UtcSeconds> {
        match self {
            DateTime::Utc { seconds, .. } => Some(*seconds),
            DateTime::Parsed(xs) => xs.to_utc(),
        }
    }

    pub fn local_day_start(&self) -> UtcSeconds {
        match self {
            DateTime::Utc { seconds, .. } => UtcSeconds(
                seconds
                    .0
                    .saturating_sub(seconds.0.rem_euclid(SECONDS_PER_DAY)),
            ),
            DateTime::Parsed(xs) => LocalDateTime {
                hour: 0,
                minute: 0,
                second: 0,
                nanos: 0,
                ..xs.local
            }
            .to_unix_seconds(),
        }
    }

    pub fn is_floating(&self) -> bool {
        matches!(
            self,
            DateTime::Parsed(XsDateTime {
                zone: XsZone::Floating,
                ..
            })
        )
    }

    pub fn parse_text(text: &str) -> Option<Self> {
        XsDateTime::parse(text.trim_ascii().as_bytes()).map(DateTime::Parsed)
    }

    fn parts(&self) -> (UtcSeconds, u16, XsForm) {
        match self {
            DateTime::Utc { seconds, millis } => (*seconds, *millis, XsForm::Utc),
            DateTime::Parsed(xs) => {
                let millis = u16::try_from(xs.local.nanos / 1_000_000).unwrap_or(0);
                match xs.to_utc() {
                    Some(seconds) => (seconds, millis, XsForm::Utc),
                    None => (floating_as_utc(&xs.local), millis, XsForm::Floating),
                }
            }
        }
    }

    pub fn write_text(&self, w: &mut XmlWriter<'_>) {
        let (seconds, millis, form) = self.parts();
        let precision = if w.millis() {
            Precision::Millis(millis)
        } else {
            Precision::Seconds
        };
        w.text_datetime(seconds, precision, form);
    }

    pub fn write_attr(&self, w: &mut XmlWriter<'_>, name: &str) {
        let (seconds, millis, form) = self.parts();
        let precision = if w.millis() {
            Precision::Millis(millis)
        } else {
            Precision::Seconds
        };
        w.attr_datetime(name, seconds, precision, form);
    }
}

fn floating_as_utc(local: &LocalDateTime) -> UtcSeconds {
    local.to_unix_seconds()
}

impl<'x> EwsValue<'x> for DateTime {
    fn parse(p: &mut Parser<'x>, _: &Attrs<'x>) -> Result<Self> {
        let text = p.text()?;
        DateTime::parse_text(&text).ok_or_else(|| p.error(ParseErrorKind::InvalidValue("dateTime")))
    }

    fn write(&self, w: &mut XmlWriter<'_>, local: &str) {
        w.start(T, local);
        self.write_text(w);
        w.end(T, local);
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Present;

impl<'x> EwsValue<'x> for Present {
    fn parse(p: &mut Parser<'x>, _: &Attrs<'x>) -> Result<Self> {
        p.skip_rest()?;
        Ok(Present)
    }

    fn write(&self, _: &mut XmlWriter<'_>, _: &str) {}
}

impl<'x> EwsValue<'x> for XsDuration {
    fn parse(p: &mut Parser<'x>, _: &Attrs<'x>) -> Result<Self> {
        p.value("duration")
    }

    fn write(&self, w: &mut XmlWriter<'_>, local: &str) {
        w.start(T, local).close_start();
        self.write(w.buffer());
        w.end(T, local);
    }
}

macro_rules! text_value {
    ($($ty:ty => $name:literal),+) => {
        $(impl<'x> EwsValue<'x> for $ty {
            fn parse(p: &mut Parser<'x>, _: &Attrs<'x>) -> Result<Self> {
                p.value($name)
            }

            fn write(&self, w: &mut XmlWriter<'_>, local: &str) {
                w.start(T, local).close_start();
                <$ty>::write(self, w.buffer());
                w.end(T, local);
            }
        })+
    };
}

text_value!(XsDate => "date", XsTime => "time");

impl<'x> EwsValue<'x> for Guid {
    fn parse(p: &mut Parser<'x>, _: &Attrs<'x>) -> Result<Self> {
        p.value("guid")
    }

    fn write(&self, w: &mut XmlWriter<'_>, local: &str) {
        w.start(T, local).close_start();
        self.write_text(w.buffer(), HexCase::Lower, Braces::None);
        w.end(T, local);
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum XBinary<'x> {
    Parsed(Base64Text<'x>),
    Bytes(bytes::Bytes),
    Borrowed(&'x [u8]),
}

impl XBinary<'_> {
    pub fn write_content(&self, w: &mut XmlWriter<'_>) {
        match self {
            XBinary::Parsed(text) => w.raw(&text.0),
            XBinary::Bytes(bytes) => w.base64(bytes),
            XBinary::Borrowed(bytes) => w.base64(bytes),
        }
    }

    pub fn is_empty(&self) -> bool {
        match self {
            XBinary::Parsed(text) => text.0.is_empty(),
            XBinary::Bytes(bytes) => bytes.is_empty(),
            XBinary::Borrowed(bytes) => bytes.is_empty(),
        }
    }
}

impl<'x> EwsValue<'x> for XBinary<'x> {
    fn parse(p: &mut Parser<'x>, _: &Attrs<'x>) -> Result<Self> {
        Ok(XBinary::Parsed(parse_base64(p)?))
    }

    fn write(&self, w: &mut XmlWriter<'_>, local: &str) {
        w.start(T, local);
        self.write_content(w);
        w.end(T, local);
    }
}

pub fn parse_base64<'x>(p: &mut Parser<'x>) -> Result<Base64Text<'x>> {
    let text = p.raw_text()?;
    if !is_base64_lexical(text.as_bytes()) {
        return Err(p.error(ParseErrorKind::InvalidValue("base64Binary")));
    }
    Ok(Base64Text(match text {
        Cow::Borrowed(text) => Cow::Borrowed(text.as_bytes()),
        Cow::Owned(text) => Cow::Owned(text.into_bytes()),
    }))
}

fn is_base64_lexical(bytes: &[u8]) -> bool {
    bytes.iter().fold(true, |valid, &b| {
        valid
            & (b.is_ascii_alphanumeric()
                | (b == b'+')
                | (b == b'/')
                | (b == b'=')
                | (b == b' ')
                | (b == b'\t')
                | (b == b'\r')
                | (b == b'\n'))
    })
}

macro_rules! text_list {
    ($name:ident, $item:literal) => {
        #[derive(Debug, Clone, PartialEq, Eq, Default)]
        pub struct $name<'x>(pub Vec<Cow<'x, str>>);

        impl<'x> EwsValue<'x> for $name<'x> {
            fn parse(p: &mut Parser<'x>, _: &Attrs<'x>) -> Result<Self> {
                let mut list = Vec::new();
                while let Some(child) = p.child()? {
                    if child.local == $item {
                        p.expect_types(&child)?;
                        list.push(p.text()?);
                    } else {
                        p.skip()?;
                    }
                }
                Ok($name(list))
            }

            fn write(&self, w: &mut XmlWriter<'_>, local: &str) {
                w.start(T, local);
                for value in &self.0 {
                    w.leaf(T, $item, value);
                }
                w.end(T, local);
            }
        }
    };
}

text_list!(Strings, "String");
text_list!(Attributions, "Attribution");
text_list!(StringValues, "Value");
text_list!(ItemClasses, "ItemClass");

impl<'x, V: EwsValue<'x>> EwsValue<'x> for Box<V> {
    fn parse(p: &mut Parser<'x>, attrs: &Attrs<'x>) -> Result<Self> {
        V::parse(p, attrs).map(Box::new)
    }

    fn write(&self, w: &mut XmlWriter<'_>, local: &str) {
        V::write(self, w, local);
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Repeated<V>(pub Vec<V>);

impl<'x, V: EwsValue<'x>> EwsValue<'x> for Repeated<V> {
    fn parse(p: &mut Parser<'x>, attrs: &Attrs<'x>) -> Result<Self> {
        Ok(Repeated(vec![V::parse(p, attrs)?]))
    }

    fn merge(slot: &mut Option<Self>, p: &mut Parser<'x>, attrs: &Attrs<'x>) -> Result<()> {
        let value = V::parse(p, attrs)?;
        slot.get_or_insert_with(|| Repeated(Vec::new()))
            .0
            .push(value);
        Ok(())
    }

    fn write(&self, w: &mut XmlWriter<'_>, local: &str) {
        for value in &self.0 {
            value.write(w, local);
        }
    }
}

pub trait ListItem {
    const ITEM: &'static str;
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct List<V>(pub Vec<V>);

impl<'x, V: EwsValue<'x> + ListItem> EwsValue<'x> for List<V> {
    fn parse(p: &mut Parser<'x>, _: &Attrs<'x>) -> Result<Self> {
        let mut list = Vec::new();
        while let Some(child) = p.child()? {
            if child.local == V::ITEM {
                p.expect_types(&child)?;
                p.count_id()?;
                list.push(V::parse(p, &child.attrs)?);
            } else {
                p.skip()?;
            }
        }
        Ok(List(list))
    }

    fn write(&self, w: &mut XmlWriter<'_>, local: &str) {
        w.start(T, local);
        for value in &self.0 {
            value.write(w, V::ITEM);
        }
        w.end(T, local);
    }
}

impl ListItem for XBinary<'_> {
    const ITEM: &'static str = "Base64Binary";
}

pub fn parse_bounded(p: &mut Parser<'_>, name: &'static str, min: u16, max: u16) -> Result<u16> {
    let value: i64 = p.value(name)?;
    u16::try_from(value)
        .ok()
        .filter(|value| (min..=max).contains(value))
        .ok_or_else(|| p.error(ParseErrorKind::InvalidValue(name)))
}

pub fn parse_list<'x, V>(
    p: &mut Parser<'x>,
    mut item: impl FnMut(&mut Parser<'x>, &Child<'x>) -> Result<Option<V>>,
) -> Result<Vec<V>> {
    let mut list = Vec::new();
    while let Some(child) = p.child()? {
        match item(p, &child)? {
            Some(value) => list.push(value),
            None => p.skip()?,
        }
    }
    Ok(list)
}

macro_rules! ews_fields {
    ($(#[$meta:meta])* $vis:vis struct $name:ident {
        $($field:ident : $el:literal => $ty:ty),+ $(,)?
    } $(skip { $($skip:literal),+ $(,)? })?) => {
        $(#[$meta])*
        #[derive(Debug, Clone, PartialEq, Default)]
        $vis struct $name {
            $(pub $field: Option<$ty>),+
        }

        $crate::ews::types::value::ews_fields!(@impl [] ['p] [<'p>] $name
            { $($field : $el => $ty),+ } [$($($skip),+)?]);
    };
    ($(#[$meta:meta])* $vis:vis struct $name:ident<$lt:lifetime> {
        $($field:ident : $el:literal => $ty:ty),+ $(,)?
    } $(skip { $($skip:literal),+ $(,)? })?) => {
        $(#[$meta])*
        #[derive(Debug, Clone, PartialEq, Default)]
        $vis struct $name<$lt> {
            $(pub $field: Option<$ty>),+
        }

        $crate::ews::types::value::ews_fields!(@impl [<$lt>] [$lt] [] $name<$lt>
            { $($field : $el => $ty),+ } [$($($skip),+)?]);
    };
    (@impl [$($impl_gen:tt)*] [$plt:lifetime] [$($fn_gen:tt)*] $name:ident $(<$lt:lifetime>)?
        { $($field:ident : $el:literal => $ty:ty),+ } [$($skip:literal),*]) => {
        impl $($impl_gen)* $name $(<$lt>)? {
            pub fn parse_child $($fn_gen)* (
                &mut self,
                p: &mut $crate::ews::parser::Parser<$plt>,
                child: &$crate::ews::parser::Child<$plt>,
            ) -> $crate::ews::parser::Result<bool> {
                hashify::fnc_map!(child.local.as_bytes(),
                    $($el => {
                        p.expect_types(child)?;
                        <$ty as $crate::ews::types::value::EwsValue>::merge(&mut self.$field, p, &child.attrs)?;
                        return Ok(true);
                    },)+
                    $($skip => {
                        p.expect_types(child)?;
                        p.skip()?;
                        return Ok(true);
                    },)*
                    _ => {
                        return Ok(false);
                    }
                )
            }

            #[allow(dead_code)]
            pub fn write_fields(&self, w: &mut $crate::xml::XmlWriter<'_>) {
                $(if let Some(value) = &self.$field {
                    $crate::ews::types::value::EwsValue::write(value, w, $el);
                })+
            }

            #[allow(dead_code)]
            pub fn is_empty(&self) -> bool {
                true $(&& self.$field.is_none())+
            }

            #[allow(dead_code)]
            pub fn field_count(&self) -> usize {
                0 $(+ usize::from(self.$field.is_some()))+
            }
        }
    };
}

macro_rules! enum_set {
    ($(#[$meta:meta])* $vis:vis struct $name:ident($enum:ty)) => {
        $(#[$meta])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
        $vis struct $name(u16);

        const _: () = assert!(<$enum>::ALL.len() <= 16);

        impl $name {
            pub fn contains(self, value: $enum) -> bool {
                self.0 & (1 << value as u16) != 0
            }

            pub fn insert(&mut self, value: $enum) {
                self.0 |= 1 << value as u16;
            }

            pub fn iter(self) -> impl Iterator<Item = $enum> {
                <$enum>::ALL
                    .iter()
                    .copied()
                    .filter(move |value| self.contains(*value))
            }

            pub fn is_empty(self) -> bool {
                self.0 == 0
            }
        }

        impl FromIterator<$enum> for $name {
            fn from_iter<I: IntoIterator<Item = $enum>>(iter: I) -> Self {
                let mut set = Self::default();
                for value in iter {
                    set.insert(value);
                }
                set
            }
        }
    };
    ($(#[$meta:meta])* $vis:vis struct $name:ident($enum:ty) list $label:literal) => {
        $crate::ews::types::value::enum_set!($(#[$meta])* $vis struct $name($enum));

        impl<'x> $crate::ews::types::value::EwsValue<'x> for $name {
            fn parse(
                p: &mut $crate::ews::parser::Parser<'x>,
                _: &$crate::xml::Attrs<'x>,
            ) -> $crate::ews::parser::Result<Self> {
                let text = p.text()?;
                let mut set = Self::default();
                for name in text.split_ascii_whitespace() {
                    set.insert(<$enum>::parse(name.as_bytes()).ok_or_else(|| {
                        p.error($crate::ews::parser::ParseErrorKind::InvalidValue($label))
                    })?);
                }
                Ok(set)
            }

            fn write(&self, w: &mut $crate::xml::XmlWriter<'_>, local: &str) {
                w.start($crate::ews::types::value::T, local).close_start();
                for (pos, value) in self.iter().enumerate() {
                    if pos > 0 {
                        w.raw(b" ");
                    }
                    w.raw(value.as_str().as_bytes());
                }
                w.end($crate::ews::types::value::T, local);
            }
        }
    };
}

macro_rules! ews_struct {
    ($(#[$meta:meta])* $vis:vis struct $name:ident {
        $($field:ident : $kind:ident $el:literal => $ty:ty),+ $(,)?
    }) => {
        $(#[$meta])*
        #[derive(Debug, Clone, PartialEq)]
        $vis struct $name {
            $(pub $field: $crate::ews::types::value::ews_struct!(@ty $kind $ty)),+
        }

        impl $name {
            $crate::ews::types::value::ews_struct!(@children { $($field : $kind $el),+ });
        }

        $crate::ews::types::value::ews_struct!(@impl ['x] $name [] { $($field : $kind $el => $ty),+ });
    };
    ($(#[$meta:meta])* $vis:vis struct $name:ident<$lt:lifetime> {
        $($field:ident : $kind:ident $el:literal => $ty:ty),+ $(,)?
    }) => {
        $(#[$meta])*
        #[derive(Debug, Clone, PartialEq)]
        $vis struct $name<$lt> {
            $(pub $field: $crate::ews::types::value::ews_struct!(@ty $kind $ty)),+
        }

        impl<$lt> $name<$lt> {
            $crate::ews::types::value::ews_struct!(@children { $($field : $kind $el),+ });
        }

        $crate::ews::types::value::ews_struct!(@impl [$lt] $name [<$lt>] { $($field : $kind $el => $ty),+ });
    };
    (@impl [$lt:lifetime] $name:ident [$($gen:tt)*] { $($field:ident : $kind:ident $el:literal => $ty:ty),+ }) => {
        impl<$lt> $crate::ews::types::value::EwsValue<$lt> for $name $($gen)* {
            fn parse(
                p: &mut $crate::ews::parser::Parser<$lt>,
                _: &$crate::xml::Attrs<$lt>,
            ) -> $crate::ews::parser::Result<Self> {
                $(let mut $field: Option<$ty> = None;)+
                while let Some(child) = p.child()? {
                    hashify::fnc_map!(child.local.as_bytes(),
                        $($el => {
                            p.expect_types(&child)?;
                            <$ty as $crate::ews::types::value::EwsValue>::merge(&mut $field, p, &child.attrs)?;
                        },)+
                        _ => {
                            p.skip()?;
                        }
                    );
                }
                Ok($name {
                    $($field: $crate::ews::types::value::ews_struct!(@finish p $kind $field $el)),+
                })
            }

            fn write(&self, w: &mut $crate::xml::XmlWriter<'_>, local: &str) {
                w.start($crate::ews::types::value::T, local);
                self.write_children(w);
                w.end($crate::ews::types::value::T, local);
            }
        }
    };
    (@children { $($field:ident : $kind:ident $el:literal),+ }) => {
        pub fn write_children(&self, w: &mut $crate::xml::XmlWriter<'_>) {
            $($crate::ews::types::value::ews_struct!(@write w $kind self.$field, $el);)+
        }
    };
    (@ty req $ty:ty) => { $ty };
    (@ty opt $ty:ty) => { Option<$ty> };
    (@finish $p:ident req $f:ident $el:literal) => {
        $f.ok_or_else(|| $p.error($crate::ews::parser::ParseErrorKind::MissingElement($el)))?
    };
    (@finish $p:ident opt $f:ident $el:literal) => { $f };
    (@write $w:ident req $value:expr, $el:literal) => {
        $crate::ews::types::value::EwsValue::write(&$value, $w, $el)
    };
    (@write $w:ident opt $value:expr, $el:literal) => {
        if let Some(value) = &$value {
            $crate::ews::types::value::EwsValue::write(value, $w, $el);
        }
    };
}

macro_rules! fields_value {
    ($name:ident<$lt:lifetime>) => {
        impl<$lt> $crate::ews::types::value::EwsValue<$lt> for $name<$lt> {
            fn parse(
                p: &mut $crate::ews::parser::Parser<$lt>,
                _: &$crate::xml::Attrs<$lt>,
            ) -> $crate::ews::parser::Result<Self> {
                let mut fields = Self::default();
                while let Some(child) = p.child()? {
                    if !fields.parse_child(p, &child)? {
                        p.skip()?;
                    }
                }
                Ok(fields)
            }

            fn write(&self, w: &mut $crate::xml::XmlWriter<'_>, local: &str) {
                w.start($crate::ews::types::value::T, local);
                self.write_fields(w);
                w.end($crate::ews::types::value::T, local);
            }
        }
    };
    ($name:ident) => {
        impl<'x> $crate::ews::types::value::EwsValue<'x> for $name {
            fn parse(
                p: &mut $crate::ews::parser::Parser<'x>,
                _: &$crate::xml::Attrs<'x>,
            ) -> $crate::ews::parser::Result<Self> {
                let mut fields = Self::default();
                while let Some(child) = p.child()? {
                    if !fields.parse_child(p, &child)? {
                        p.skip()?;
                    }
                }
                Ok(fields)
            }

            fn write(&self, w: &mut $crate::xml::XmlWriter<'_>, local: &str) {
                w.start($crate::ews::types::value::T, local);
                self.write_fields(w);
                w.end($crate::ews::types::value::T, local);
            }
        }
    };
}

pub(crate) use {enum_set, ews_fields, ews_struct, fields_value};
