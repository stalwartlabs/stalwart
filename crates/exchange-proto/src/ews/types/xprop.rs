/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::value::{DateTime, EwsValue, T, write_f64};
use crate::{
    common::{Base64Text, Braces, FileTime, Guid, HexCase, XsDateTime},
    ews::{
        parser::{ParseErrorKind, Parser, Result},
        schema::{DistinguishedPropertySet, MapiPropertyTypeName},
    },
    mapi::{
        ec::ErrorCode,
        prop::{OwnedPropValue, PropId, PropKey, PropKeyRef, PropType},
    },
    xml::{
        Attrs, XmlWriter,
        value::{parse_bool, parse_f64, parse_hex_or_decimal},
        writer::bool_str,
    },
};
use std::borrow::Cow;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtendedFieldUri<'a> {
    pub target: XPropTarget<'a>,
    pub ptype: MapiPropertyTypeName,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum XPropTarget<'a> {
    Tag(u16),
    Named { set: XPropSet, id: XPropNamedId<'a> },
    InvalidCombination,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum XPropSet {
    Distinguished(DistinguishedPropertySet),
    Guid(Guid),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum XPropNamedId<'a> {
    Id(i32),
    Name(Cow<'a, str>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtendedProperty<'a> {
    pub uri: ExtendedFieldUri<'a>,
    pub value: XPropValue<'a>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum XPropValue<'a> {
    Single(Cow<'a, str>),
    Multi(Vec<Cow<'a, str>>),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum XPropError {
    InvalidCombination,
    NamedRangeTag,
    UnsupportedType,
    ShapeMismatch,
    InvalidValue,
}

impl XPropSet {
    pub fn guid(self) -> Guid {
        match self {
            XPropSet::Distinguished(set) => set.data(),
            XPropSet::Guid(guid) => guid,
        }
    }

    pub fn from_guid(guid: Guid) -> Self {
        DistinguishedPropertySet::ALL
            .iter()
            .find(|set| set.data() == guid)
            .map_or(XPropSet::Guid(guid), |set| XPropSet::Distinguished(*set))
    }
}

impl<'a> ExtendedFieldUri<'a> {
    pub fn parse_attrs(p: &Parser<'a>, attrs: &Attrs<'a>) -> Result<Self> {
        let uri = Self::parse_lenient(p, attrs)?;
        if uri.target == XPropTarget::InvalidCombination {
            Err(p.error(ParseErrorKind::InvalidValue("ExtendedFieldURI")))
        } else {
            Ok(uri)
        }
    }

    fn parse_lenient(p: &Parser<'a>, attrs: &Attrs<'a>) -> Result<Self> {
        let ptype = p
            .attr_enum(attrs, "PropertyType", MapiPropertyTypeName::parse)?
            .ok_or_else(|| p.error(ParseErrorKind::MissingAttribute("PropertyType")))?;
        let tag = p.attr(attrs, "PropertyTag")?;
        let distinguished = p.attr_enum(
            attrs,
            "DistinguishedPropertySetId",
            DistinguishedPropertySet::parse,
        )?;
        let guid: Option<Guid> = p.attr_value(attrs, "PropertySetId")?;
        let name = p.attr(attrs, "PropertyName")?;
        let id: Option<i32> = p.attr_value(attrs, "PropertyId")?;

        let target = match (tag, distinguished, guid) {
            (Some(tag), None, None) if name.is_none() && id.is_none() => XPropTarget::Tag(
                parse_hex_or_decimal(&tag)
                    .and_then(|tag| u16::try_from(tag).ok())
                    .ok_or_else(|| p.error(ParseErrorKind::InvalidValue("ExtendedFieldURI")))?,
            ),
            (None, Some(set), None) => named_target(XPropSet::Distinguished(set), name, id),
            (None, None, Some(guid)) => named_target(XPropSet::Guid(guid), name, id),
            _ => XPropTarget::InvalidCombination,
        };
        Ok(ExtendedFieldUri { target, ptype })
    }

    pub fn write_attrs(&self, w: &mut XmlWriter<'_>) {
        match &self.target {
            XPropTarget::Tag(tag) => {
                let mut hex = [0u8; 6];
                w.attr("PropertyTag", tag_hex(*tag, &mut hex));
            }
            XPropTarget::Named { set, id } => {
                match set {
                    XPropSet::Distinguished(set) => {
                        w.attr("DistinguishedPropertySetId", set.as_str());
                    }
                    XPropSet::Guid(guid) => {
                        let mut text = Vec::with_capacity(36);
                        guid.write_text(&mut text, HexCase::Lower, Braces::None);
                        w.attr(
                            "PropertySetId",
                            std::str::from_utf8(&text).unwrap_or_default(),
                        );
                    }
                }
                match id {
                    XPropNamedId::Id(id) => {
                        w.attr_i64("PropertyId", i64::from(*id));
                    }
                    XPropNamedId::Name(name) => {
                        w.attr("PropertyName", name);
                    }
                }
            }
            XPropTarget::InvalidCombination => {}
        }
        w.attr("PropertyType", self.ptype.as_str());
    }

    pub fn to_prop(&self) -> std::result::Result<(PropKey, PropType), XPropError> {
        let ptype = PropType::from_code(self.ptype.data());
        let key = match &self.target {
            XPropTarget::Tag(tag) => {
                let id = PropId(*tag);
                if id.is_named() {
                    return Err(XPropError::NamedRangeTag);
                }
                PropKey::tag(id)
            }
            XPropTarget::Named { set, id } => match id {
                XPropNamedId::Id(id) => PropKey::lid(set.guid(), id.cast_unsigned()),
                XPropNamedId::Name(name) => PropKey::name(set.guid(), name),
            },
            XPropTarget::InvalidCombination => return Err(XPropError::InvalidCombination),
        };
        Ok((key, ptype))
    }

    pub fn from_prop(key: &PropKey, ptype: PropType) -> ExtendedFieldUri<'static> {
        let target = match key.as_ref() {
            PropKeyRef::Tag(id) => XPropTarget::Tag(id.0),
            PropKeyRef::Lid { set, lid } => XPropTarget::Named {
                set: XPropSet::from_guid(set),
                id: XPropNamedId::Id(lid.cast_signed()),
            },
            PropKeyRef::Name { set, name } => XPropTarget::Named {
                set: XPropSet::from_guid(set),
                id: XPropNamedId::Name(Cow::Owned(name.to_owned())),
            },
        };
        ExtendedFieldUri {
            target,
            ptype: type_name(ptype),
        }
    }
}

impl<'a> EwsValue<'a> for ExtendedFieldUri<'a> {
    fn parse(p: &mut Parser<'a>, attrs: &Attrs<'a>) -> Result<Self> {
        let uri = Self::parse_attrs(p, attrs)?;
        p.skip_rest()?;
        Ok(uri)
    }

    fn write(&self, w: &mut XmlWriter<'_>, local: &str) {
        w.start(T, local);
        self.write_attrs(w);
        w.empty();
    }
}

fn named_target<'a>(set: XPropSet, name: Option<Cow<'a, str>>, id: Option<i32>) -> XPropTarget<'a> {
    match (name, id) {
        (Some(name), None) => XPropTarget::Named {
            set,
            id: XPropNamedId::Name(name),
        },
        (None, Some(id)) => XPropTarget::Named {
            set,
            id: XPropNamedId::Id(id),
        },
        _ => XPropTarget::InvalidCombination,
    }
}

fn tag_hex(tag: u16, buf: &mut [u8; 6]) -> &str {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let digits = (4 - tag.leading_zeros() / 4).max(1) as usize;
    let (prefix, rest) = buf.split_at_mut(2);
    prefix.copy_from_slice(b"0x");
    for (slot, shift) in rest
        .iter_mut()
        .zip((0..digits).rev().map(|digit| digit * 4))
    {
        *slot = HEX[usize::from((tag >> shift) & 0xF)];
    }
    buf.get(..2 + digits)
        .and_then(|text| std::str::from_utf8(text).ok())
        .unwrap_or_default()
}

fn type_name(ptype: PropType) -> MapiPropertyTypeName {
    use MapiPropertyTypeName as N;
    match ptype {
        PropType::Null => N::Null,
        PropType::I16 => N::Short,
        PropType::I32 => N::Integer,
        PropType::F32 => N::Float,
        PropType::F64 => N::Double,
        PropType::Currency => N::Currency,
        PropType::AppTime => N::ApplicationTime,
        PropType::Error => N::Error,
        PropType::Bool => N::Boolean,
        PropType::Object => N::Object,
        PropType::I64 => N::Long,
        PropType::String8 | PropType::Unicode | PropType::CodePageString(_) => N::String,
        PropType::Time => N::SystemTime,
        PropType::Guid => N::Clsid,
        PropType::MvI16 => N::ShortArray,
        PropType::MvI32 => N::IntegerArray,
        PropType::MvF32 => N::FloatArray,
        PropType::MvF64 => N::DoubleArray,
        PropType::MvCurrency => N::CurrencyArray,
        PropType::MvAppTime => N::ApplicationTimeArray,
        PropType::MvI64 => N::LongArray,
        PropType::MvString8 | PropType::MvUnicode => N::StringArray,
        PropType::MvTime => N::SystemTimeArray,
        PropType::MvGuid => N::CLSIDArray,
        PropType::MvBinary => N::BinaryArray,
        PropType::Binary
        | PropType::ServerId
        | PropType::Restriction
        | PropType::RuleAction
        | PropType::Unspecified
        | PropType::Unknown(_) => N::Binary,
    }
}

impl<'a> EwsValue<'a> for ExtendedProperty<'a> {
    fn parse(p: &mut Parser<'a>, _: &Attrs<'a>) -> Result<Self> {
        let mut uri = None;
        let mut value = None;
        while let Some(child) = p.child()? {
            hashify::fnc_map!(child.local.as_bytes(),
                "ExtendedFieldURI" => {
                    p.expect_types(&child)?;
                    uri = Some(ExtendedFieldUri::parse_lenient(p, &child.attrs)?);
                    p.skip_rest()?;
                },
                "Value" => {
                    p.expect_types(&child)?;
                    value = Some(XPropValue::Single(p.text()?));
                },
                "Values" => {
                    p.expect_types(&child)?;
                    let mut list = Vec::new();
                    while let Some(item) = p.child()? {
                        if item.local == "Value" {
                            p.expect_types(&item)?;
                            list.push(p.text()?);
                        } else {
                            p.skip()?;
                        }
                    }
                    value = Some(XPropValue::Multi(list));
                },
                _ => {
                    p.skip()?;
                }
            );
        }
        Ok(ExtendedProperty {
            uri: uri.ok_or_else(|| p.error(ParseErrorKind::MissingElement("ExtendedFieldURI")))?,
            value: value.ok_or_else(|| p.error(ParseErrorKind::MissingElement("Value")))?,
        })
    }

    fn write(&self, w: &mut XmlWriter<'_>, local: &str) {
        w.start(T, local);
        self.uri.write(w, "ExtendedFieldURI");
        match &self.value {
            XPropValue::Single(value) => w.leaf(T, "Value", value),
            XPropValue::Multi(values) => {
                w.start(T, "Values");
                for value in values {
                    w.leaf(T, "Value", value);
                }
                w.end(T, "Values");
            }
        }
        w.end(T, local);
    }
}

impl<'a> XPropValue<'a> {
    pub fn from_owned(value: &'a OwnedPropValue) -> Self {
        match MultiRef::of(value) {
            Some(multi) => XPropValue::Multi(multi.texts()),
            None => XPropValue::Single(scalar_text(value)),
        }
    }

    pub fn to_owned_value(
        &self,
        ptype: PropType,
    ) -> std::result::Result<OwnedPropValue, XPropError> {
        match (self, ptype.is_multi()) {
            (XPropValue::Single(text), false) => scalar(text, ptype),
            (XPropValue::Multi(list), true) => multi(list, ptype),
            _ => Err(XPropError::ShapeMismatch),
        }
    }
}

fn parse_num<N: std::str::FromStr>(text: &str) -> std::result::Result<N, XPropError> {
    text.trim_ascii()
        .parse()
        .map_err(|_| XPropError::InvalidValue)
}

fn parse_float(text: &str) -> std::result::Result<f64, XPropError> {
    parse_f64(text).ok_or(XPropError::InvalidValue)
}

fn parse_time(text: &str) -> std::result::Result<FileTime, XPropError> {
    let xs = XsDateTime::parse(text.trim_ascii().as_bytes()).ok_or(XPropError::InvalidValue)?;
    let seconds = xs.to_utc().unwrap_or_else(|| xs.local.to_unix_seconds());
    Ok(FileTime::from_utc(seconds, xs.local.nanos))
}

fn parse_guid(text: &str) -> std::result::Result<Guid, XPropError> {
    Guid::parse_text(text.trim_ascii().as_bytes()).ok_or(XPropError::InvalidValue)
}

fn parse_binary(text: &str) -> std::result::Result<bytes::Bytes, XPropError> {
    let encoded = Base64Text(Cow::Borrowed(text.as_bytes()));
    let mut out = Vec::with_capacity(encoded.decoded_len_max());
    encoded
        .decode_into(&mut out, encoded.decoded_len_max())
        .map_err(|_| XPropError::InvalidValue)?;
    Ok(bytes::Bytes::from(out))
}

fn scalar(text: &str, ptype: PropType) -> std::result::Result<OwnedPropValue, XPropError> {
    Ok(match ptype {
        PropType::Null => OwnedPropValue::Null,
        PropType::I16 => OwnedPropValue::I16(parse_num(text)?),
        PropType::I32 => OwnedPropValue::I32(parse_num(text)?),
        PropType::I64 => OwnedPropValue::I64(parse_num(text)?),
        PropType::Currency => OwnedPropValue::Currency(parse_num(text)?),
        PropType::F32 => OwnedPropValue::F32(parse_float(text)? as f32),
        PropType::F64 => OwnedPropValue::F64(parse_float(text)?),
        PropType::AppTime => OwnedPropValue::AppTime(parse_float(text)?),
        PropType::Error => OwnedPropValue::Error(ErrorCode(
            parse_hex_or_decimal(text)
                .and_then(|code| u32::try_from(code).ok())
                .ok_or(XPropError::InvalidValue)?,
        )),
        PropType::Bool => OwnedPropValue::Bool(parse_bool(text).ok_or(XPropError::InvalidValue)?),
        PropType::Time => OwnedPropValue::Time(parse_time(text)?),
        PropType::Guid => OwnedPropValue::Guid(parse_guid(text)?),
        PropType::String8 | PropType::Unicode => OwnedPropValue::Unicode(Box::from(text)),
        PropType::Binary => OwnedPropValue::Binary(parse_binary(text)?),
        _ => return Err(XPropError::UnsupportedType),
    })
}

fn collect<T>(
    list: &[Cow<'_, str>],
    parse: impl Fn(&str) -> std::result::Result<T, XPropError>,
) -> std::result::Result<Box<[T]>, XPropError> {
    list.iter().map(|text| parse(text)).collect()
}

fn multi(
    list: &[Cow<'_, str>],
    ptype: PropType,
) -> std::result::Result<OwnedPropValue, XPropError> {
    Ok(match ptype {
        PropType::MvI16 => OwnedPropValue::MvI16(collect(list, parse_num)?),
        PropType::MvI32 => OwnedPropValue::MvI32(collect(list, parse_num)?),
        PropType::MvI64 => OwnedPropValue::MvI64(collect(list, parse_num)?),
        PropType::MvCurrency => OwnedPropValue::MvCurrency(collect(list, parse_num)?),
        PropType::MvF32 => {
            OwnedPropValue::MvF32(collect(list, |text| parse_float(text).map(|v| v as f32))?)
        }
        PropType::MvF64 => OwnedPropValue::MvF64(collect(list, parse_float)?),
        PropType::MvAppTime => OwnedPropValue::MvAppTime(collect(list, parse_float)?),
        PropType::MvTime => OwnedPropValue::MvTime(collect(list, parse_time)?),
        PropType::MvGuid => OwnedPropValue::MvGuid(collect(list, parse_guid)?),
        PropType::MvString8 | PropType::MvUnicode => {
            OwnedPropValue::MvUnicode(list.iter().map(|text| Box::from(text.as_ref())).collect())
        }
        PropType::MvBinary => OwnedPropValue::MvBinary(collect(list, parse_binary)?),
        _ => return Err(XPropError::UnsupportedType),
    })
}

fn write_time(value: FileTime, w: &mut XmlWriter<'_>) {
    let (seconds, nanos) = value.to_utc();
    DateTime::Utc {
        seconds,
        millis: u16::try_from(nanos / 1_000_000).unwrap_or(0),
    }
    .write_text(w);
}

fn write_guid(value: &Guid, w: &mut XmlWriter<'_>) {
    w.close_start();
    value.write_text(w.buffer(), HexCase::Lower, Braces::None);
}

fn plain_text(write: impl FnOnce(&mut XmlWriter<'_>)) -> Cow<'static, str> {
    let mut out = Vec::new();
    write(&mut XmlWriter::new(&mut out));
    Cow::Owned(String::from_utf8(out).unwrap_or_default())
}

fn scalar_text(value: &OwnedPropValue) -> Cow<'_, str> {
    match value {
        OwnedPropValue::Unicode(text) => Cow::Borrowed(text),
        OwnedPropValue::String8(text) => String::from_utf8_lossy(text),
        value => plain_text(|w| write_plain_scalar(value, w)),
    }
}

fn write_plain_scalar(value: &OwnedPropValue, w: &mut XmlWriter<'_>) {
    match value {
        OwnedPropValue::Null
        | OwnedPropValue::Object
        | OwnedPropValue::String8(_)
        | OwnedPropValue::Unicode(_) => {}
        OwnedPropValue::I16(v) => w.text_i64(i64::from(*v)),
        OwnedPropValue::I32(v) => w.text_i64(i64::from(*v)),
        OwnedPropValue::I64(v) | OwnedPropValue::Currency(v) => w.text_i64(*v),
        OwnedPropValue::F32(v) => write_f64(w, f64::from(*v)),
        OwnedPropValue::F64(v) | OwnedPropValue::AppTime(v) => write_f64(w, *v),
        OwnedPropValue::Error(code) => w.text_u64(u64::from(code.0)),
        OwnedPropValue::Bool(v) => w.raw(bool_str(*v).as_bytes()),
        OwnedPropValue::Time(v) => write_time(*v, w),
        OwnedPropValue::Guid(v) => write_guid(v, w),
        OwnedPropValue::Binary(v) => w.base64(v),
        OwnedPropValue::ServerId(v)
        | OwnedPropValue::Restriction(v)
        | OwnedPropValue::RuleAction(v) => w.base64(v),
        OwnedPropValue::MvI16(_)
        | OwnedPropValue::MvI32(_)
        | OwnedPropValue::MvF32(_)
        | OwnedPropValue::MvF64(_)
        | OwnedPropValue::MvCurrency(_)
        | OwnedPropValue::MvAppTime(_)
        | OwnedPropValue::MvI64(_)
        | OwnedPropValue::MvTime(_)
        | OwnedPropValue::MvGuid(_)
        | OwnedPropValue::MvString8(_)
        | OwnedPropValue::MvUnicode(_)
        | OwnedPropValue::MvBinary(_) => {}
    }
}

enum MultiRef<'v> {
    I16(&'v [i16]),
    I32(&'v [i32]),
    I64(&'v [i64]),
    F32(&'v [f32]),
    F64(&'v [f64]),
    Time(&'v [FileTime]),
    Guid(&'v [Guid]),
    String8(&'v [Box<[u8]>]),
    Unicode(&'v [Box<str>]),
    Binary(&'v [bytes::Bytes]),
}

impl<'v> MultiRef<'v> {
    fn of(value: &'v OwnedPropValue) -> Option<Self> {
        Some(match value {
            OwnedPropValue::MvI16(v) => MultiRef::I16(v),
            OwnedPropValue::MvI32(v) => MultiRef::I32(v),
            OwnedPropValue::MvI64(v) | OwnedPropValue::MvCurrency(v) => MultiRef::I64(v),
            OwnedPropValue::MvF32(v) => MultiRef::F32(v),
            OwnedPropValue::MvF64(v) | OwnedPropValue::MvAppTime(v) => MultiRef::F64(v),
            OwnedPropValue::MvTime(v) => MultiRef::Time(v),
            OwnedPropValue::MvGuid(v) => MultiRef::Guid(v),
            OwnedPropValue::MvString8(v) => MultiRef::String8(v),
            OwnedPropValue::MvUnicode(v) => MultiRef::Unicode(v),
            OwnedPropValue::MvBinary(v) => MultiRef::Binary(v),
            _ => return None,
        })
    }

    fn texts(self) -> Vec<Cow<'v, str>> {
        fn each<'v, T>(
            list: &'v [T],
            text: impl FnMut(&'v T) -> Cow<'v, str>,
        ) -> Vec<Cow<'v, str>> {
            list.iter().map(text).collect()
        }
        match self {
            MultiRef::I16(list) => each(list, |v| Cow::Owned(v.to_string())),
            MultiRef::I32(list) => each(list, |v| Cow::Owned(v.to_string())),
            MultiRef::I64(list) => each(list, |v| Cow::Owned(v.to_string())),
            MultiRef::F32(list) => each(list, |v| plain_text(|w| write_f64(w, f64::from(*v)))),
            MultiRef::F64(list) => each(list, |v| plain_text(|w| write_f64(w, *v))),
            MultiRef::Time(list) => each(list, |v| plain_text(|w| write_time(*v, w))),
            MultiRef::Guid(list) => each(list, |v| plain_text(|w| write_guid(v, w))),
            MultiRef::String8(list) => each(list, |v| String::from_utf8_lossy(v)),
            MultiRef::Unicode(list) => each(list, |v| Cow::Borrowed(v.as_ref())),
            MultiRef::Binary(list) => each(list, |v| plain_text(|w| w.base64(v))),
        }
    }
}
