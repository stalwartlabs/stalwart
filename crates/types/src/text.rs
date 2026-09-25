/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::id::Id;
use serde::{Serialize, Serializer};
use std::{
    borrow::Cow,
    fmt::{self, Display, Write},
};

#[derive(Clone, Copy)]
pub enum Text<'x> {
    Static(&'static str),
    Str(&'x str),
    Id(Id),
    Reference(&'x str),
    Display(&'x dyn Display),
}

struct Expect<'x>(&'x str);

impl<'x> Text<'x> {
    #[inline]
    pub fn to_cow(self) -> Cow<'static, str> {
        match self {
            Text::Static(text) => Cow::Borrowed(text),
            Text::Str(text) => Cow::Owned(text.to_string()),
            Text::Id(id) => Cow::Owned(id.as_string()),
            Text::Reference(reference) => Cow::Owned(format!("#{reference}")),
            Text::Display(value) => Cow::Owned(value.to_string()),
        }
    }

    #[inline]
    pub fn eq_str(self, text: &str) -> bool {
        match self {
            Text::Static(value) => value == text,
            Text::Str(value) => value == text,
            Text::Id(id) => id.text().as_str() == text,
            Text::Reference(reference) => text.strip_prefix('#') == Some(reference),
            Text::Display(value) => {
                let mut expect = Expect(text);
                write!(expect, "{value}").is_ok() && expect.0.is_empty()
            }
        }
    }

    #[inline]
    pub fn eq_text(self, other: Text<'_>) -> bool {
        match (self, other) {
            (Text::Id(a), Text::Id(b)) => a == b,
            (Text::Static(text) | Text::Str(text), other)
            | (other, Text::Static(text) | Text::Str(text)) => other.eq_str(text),
            (Text::Id(id), other) | (other, Text::Id(id)) => other.eq_str(id.text().as_str()),
            (Text::Reference(a), Text::Reference(b)) => a == b,
            (Text::Reference(_) | Text::Display(_), Text::Reference(_) | Text::Display(_)) => {
                other.eq_str(&self.to_cow())
            }
        }
    }
}

impl Serialize for Text<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self {
            Text::Static(text) => serializer.serialize_str(text),
            Text::Str(text) => serializer.serialize_str(text),
            Text::Id(id) => serializer.serialize_str(id.text().as_str()),
            Text::Reference(reference) => serializer.collect_str(&format_args!("#{reference}")),
            Text::Display(value) => serializer.collect_str(value),
        }
    }
}

impl Write for Expect<'_> {
    fn write_str(&mut self, text: &str) -> fmt::Result {
        self.0 = self.0.strip_prefix(text).ok_or(fmt::Error)?;
        Ok(())
    }
}
