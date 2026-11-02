/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{
    PartialDateTime, VCard, VCardEntry, VCardParameter, VCardParameterName, VCardType, VCardValue,
    VCardValueType, ValueSeparator, ValueType,
};
use crate::{
    Entry, Parser, Token,
    common::{
        CalendarScale, Data, Encoding, IanaParse, IanaType,
        decode::{Decoded, ValueDecoder},
        parser::{Boolean, Integer, Timestamp, parse_digits, parse_small_digits},
        tokenizer::{Mode, StopChar},
    },
    vcard::{
        Jscomp, VCardGramGender, VCardKind, VCardLevel, VCardParameterValue, VCardPhonetic,
        VCardProperty, VCardSex,
    },
};
use smallvec::{SmallVec, smallvec};
use std::{iter::Peekable, mem::take, slice::Iter};

struct Params {
    params: Vec<VCardParameter>,
    stop_char: StopChar,
    data_types: Vec<IanaType<VCardValueType, String>>,
    charset: Option<String>,
    encoding: Option<Encoding>,
    group_name: Option<String>,
}

impl VCardProperty {
    pub(crate) fn value_decoder<'x>(
        &self,
        encoding: Encoding,
        charset: Option<&'x str>,
    ) -> ValueDecoder<'x> {
        let binary = matches!(encoding, Encoding::Base64)
            && match self {
                VCardProperty::Photo
                | VCardProperty::Logo
                | VCardProperty::Sound
                | VCardProperty::Key => true,
                VCardProperty::Other(_) => charset.is_none(),
                _ => false,
            };
        ValueDecoder {
            encoding,
            charset,
            binary,
        }
    }
}

struct ValueText<'x> {
    token: Token<'x>,
    decoded: Option<String>,
}

impl<'x> ValueText<'x> {
    #[inline(always)]
    fn bytes(&self) -> &[u8] {
        match &self.decoded {
            Some(decoded) => decoded.as_bytes(),
            None => self.token.text.as_ref(),
        }
    }

    #[inline(always)]
    fn into_string(self) -> String {
        match self.decoded {
            Some(decoded) => decoded,
            None => self.token.into_string(),
        }
    }

    #[inline(always)]
    fn into_token(self) -> Token<'x> {
        let mut token = self.token;
        if let Some(decoded) = self.decoded {
            token.text = decoded.into();
        }
        token
    }
}

const BYTES_PER_ENTRY: usize = 32;
const MIN_ENTRIES: usize = 4;
const MAX_ENTRIES: usize = 32;
const MULTI_VALUES: usize = 4;
const STRUCTURED_VALUES: usize = 8;

impl Parser<'_> {
    pub fn vcard(&mut self) -> Entry {
        let mut vcard = VCard::default();
        let entries_hint = self.entries_hint();
        let mut is_v4 = true;
        let mut is_valid = false;

        'outer: loop {
            self.expect_iana_token();
            self.mode.set(Mode::STOP_DOT, true);
            let Some(mut token) = self.token() else {
                break;
            };
            self.mode.set(Mode::STOP_DOT, false);

            let mut params = Params {
                params: Vec::new(),
                stop_char: token.stop_char,
                data_types: Vec::new(),
                group_name: None,
                encoding: None,
                charset: None,
            };

            if matches!(token.stop_char, StopChar::Dot) {
                params.group_name = token.into_string().into();
                token = match self.token() {
                    Some(token) => token,
                    None => break,
                };
                params.stop_char = token.stop_char;
            }

            match params.stop_char {
                StopChar::Semicolon => {
                    self.vcard_parameters(&mut params);
                }
                StopChar::Lf => {
                    if token.text.is_empty() || !self.strict {
                        continue;
                    } else {
                        return Entry::InvalidLine(token.into_string());
                    }
                }
                _ => {}
            }

            if !matches!(params.stop_char, StopChar::Colon | StopChar::Lf) {
                params.stop_char = self.seek_value_or_eol();
            }

            let name = match VCardProperty::parse(token.text.as_ref()) {
                Some(name) => name,
                None if !token.text.is_empty() => VCardProperty::Other(token.into_string()),
                None => {
                    if params.stop_char != StopChar::Lf {
                        self.seek_lf();
                    }
                    continue;
                }
            };
            let mut entry = VCardEntry {
                group: params.group_name,
                name,
                params: params.params,
                values: SmallVec::new(),
            };

            if params.stop_char != StopChar::Lf {
                let (default_type, multi_value) = entry.name.default_types();

                let (is_structured, value_capacity) = match multi_value {
                    ValueSeparator::None => {
                        self.expect_single_value();
                        (false, 1)
                    }
                    ValueSeparator::Comma => {
                        self.expect_multi_value_comma();
                        (false, MULTI_VALUES)
                    }
                    ValueSeparator::Semicolon => {
                        self.expect_multi_value_semicolon();
                        (false, MULTI_VALUES)
                    }
                    ValueSeparator::SemicolonAndComma => {
                        self.expect_multi_value_semicolon_and_comma();
                        (true, STRUCTURED_VALUES)
                    }
                    ValueSeparator::Skip => {
                        is_valid = entry.name == VCardProperty::End;
                        self.expect_single_value();
                        self.token();
                        break 'outer;
                    }
                };
                entry.values.reserve_exact(value_capacity);
                let charset = params.charset.as_deref();
                let decoder = match params.encoding {
                    Some(Encoding::Base64) => {
                        if multi_value != ValueSeparator::None {
                            self.expect_single_value();
                        }
                        self.mode.set(Mode::UNFOLD_B64, true);
                        Some(entry.name.value_decoder(Encoding::Base64, charset))
                    }
                    Some(Encoding::QuotedPrintable) => {
                        self.mode.set(Mode::UNFOLD_QP, true);
                        Some(entry.name.value_decoder(Encoding::QuotedPrintable, charset))
                    }
                    None => None,
                };

                let mut data_types = params.data_types.iter();
                let mut token_idx = 0;
                let mut last_is_comma = false;

                let mut payload = None;
                while let Some(token) = self.value_token(params.encoding, &mut payload) {
                    let (is_eol, is_comma) = match token.stop_char {
                        StopChar::Lf => (true, false),
                        StopChar::Comma => (false, true),
                        _ => (false, false),
                    };

                    let mut text = ValueText {
                        token,
                        decoded: None,
                    };
                    if let Some(decoder) = &decoder {
                        match decoder.decode(
                            text.token.text.as_ref(),
                            text.token.stop_char,
                            payload.take(),
                        ) {
                            Decoded::Binary(data) => {
                                entry.values.push(VCardValue::Binary(Box::new(Data {
                                    data,
                                    content_type: None,
                                })));
                                if is_eol {
                                    break;
                                } else {
                                    continue;
                                }
                            }
                            Decoded::Text(decoded) => text.decoded = Some(decoded),
                            Decoded::Undecodable => {}
                        }
                    }

                    let default_type = match &default_type {
                        ValueType::Vcard(default_type) => default_type,
                        ValueType::Kind if token_idx == 0 => {
                            if let Some(value) = VCardKind::parse(text.bytes()) {
                                entry.values.push(VCardValue::Kind(value));
                                if is_eol {
                                    break;
                                } else {
                                    continue;
                                }
                            }
                            &VCardValueType::Text
                        }
                        ValueType::Sex if token_idx == 0 => {
                            if let Some(value) = VCardSex::parse(text.bytes()) {
                                entry.values.push(VCardValue::Sex(value));
                                if is_eol {
                                    break;
                                } else {
                                    continue;
                                }
                            }
                            &VCardValueType::Text
                        }
                        ValueType::GramGender if token_idx == 0 => {
                            if let Some(value) = VCardGramGender::parse(text.bytes()) {
                                entry.values.push(VCardValue::GramGender(value));
                                if is_eol {
                                    break;
                                } else {
                                    continue;
                                }
                            }
                            &VCardValueType::Text
                        }
                        _ => &VCardValueType::Text,
                    };

                    let value = match data_types.next().unwrap_or(&IanaType::Iana(*default_type)) {
                        IanaType::Iana(VCardValueType::Text) => {
                            if is_v4
                                && entry.name == VCardProperty::Version
                                && matches!(text.bytes().first(), Some(b'1'..=b'3'))
                            {
                                is_v4 = false;
                            }
                            VCardValue::Text(text.into_string())
                        }
                        IanaType::Iana(VCardValueType::LanguageTag) | IanaType::Other(_) => {
                            VCardValue::Text(text.into_string())
                        }
                        IanaType::Iana(value_type) => {
                            text.into_token().into_vcard_value(*value_type, is_v4)
                        }
                    };

                    if is_structured {
                        match (last_is_comma, entry.values.last_mut(), value) {
                            (true, Some(last), VCardValue::Text(item)) => {
                                if let Some(item) = last.extend_component(item) {
                                    entry.values.push(VCardValue::Text(item));
                                }
                            }
                            (_, _, value) => {
                                entry.values.push(value);
                            }
                        }

                        last_is_comma = is_comma;
                    } else {
                        entry.values.push(value);
                    }

                    if is_eol {
                        break;
                    }

                    token_idx += 1;
                }
            } else {
                entry.values = smallvec![VCardValue::Text(String::new())];
            }

            if !params.data_types.is_empty() {
                entry
                    .params
                    .extend(params.data_types.into_iter().map(|dt| VCardParameter {
                        name: VCardParameterName::Value,
                        value: match dt {
                            IanaType::Iana(v) => VCardParameterValue::ValueType(v),
                            IanaType::Other(v) => VCardParameterValue::Text(v),
                        },
                    }));
            }

            if !is_v4 {
                entry.normalize_legacy_media_type();
            }

            if vcard.entries.capacity() == 0 {
                self.presize(&mut vcard.entries, entries_hint);
            }
            vcard.entries.push(entry);
        }

        if is_valid || !self.strict {
            Entry::VCard(vcard)
        } else {
            Entry::UnterminatedComponent("BEGIN".into())
        }
    }

    fn entries_hint(&self) -> usize {
        (self.input.len().saturating_sub(self.pos) / BYTES_PER_ENTRY)
            .clamp(MIN_ENTRIES, MAX_ENTRIES)
    }

    fn vcard_parameters(&mut self, params: &mut Params) {
        while params.stop_char == StopChar::Semicolon {
            self.expect_iana_token();
            let Some(name_token) = self.token() else {
                params.stop_char = StopChar::Lf;
                break;
            };

            params.stop_char = name_token.stop_char;
            if !matches!(
                params.stop_char,
                StopChar::Lf | StopChar::Colon | StopChar::Semicolon
            ) {
                if params.stop_char != StopChar::Equal {
                    params.stop_char = self.seek_param_value_or_eol();
                }
                if params.stop_char == StopChar::Equal {
                    self.expect_param_value();
                    while !matches!(
                        params.stop_char,
                        StopChar::Lf | StopChar::Colon | StopChar::Semicolon
                    ) {
                        match self.token() {
                            Some(token) => {
                                params.stop_char = token.stop_char;
                                self.token_buf.push(token);
                            }
                            None => {
                                params.stop_char = StopChar::Lf;
                                break;
                            }
                        }
                    }
                }
            }

            let param_name = name_token.text.as_ref();
            let param_values = &mut params.params;
            if let Some(param_name) = VCardParameterName::try_parse(param_name) {
                if self.token_buf.is_empty() {
                    param_values.push(VCardParameter::new(param_name, VCardParameterValue::Null));
                    continue;
                }

                match param_name {
                    VCardParameterName::Value => {
                        params
                            .data_types
                            .extend(self.token_buf.drain(..).map(Into::into));
                    }
                    VCardParameterName::Pref | VCardParameterName::Index => {
                        if let Some(value) = self.buf_parse_one::<IanaType<Integer, String>>() {
                            param_values.push(VCardParameter {
                                name: param_name,
                                value: match value {
                                    IanaType::Iana(value) => {
                                        VCardParameterValue::Integer(value.0 as u32)
                                    }
                                    IanaType::Other(value) => VCardParameterValue::Text(value),
                                },
                            });
                        }
                    }
                    VCardParameterName::Calscale => {
                        if let Some(value) = self.buf_parse_one::<IanaType<CalendarScale, String>>()
                        {
                            param_values.push(VCardParameter::new(param_name, value));
                        }
                    }
                    VCardParameterName::Phonetic => {
                        if let Some(value) = self.buf_parse_one::<IanaType<VCardPhonetic, String>>()
                        {
                            param_values.push(VCardParameter::new(param_name, value));
                        }
                    }
                    VCardParameterName::Level => {
                        if let Some(value) = self.buf_parse_one::<IanaType<VCardLevel, String>>() {
                            param_values.push(VCardParameter::new(param_name, value));
                        }
                    }
                    VCardParameterName::Created => {
                        if let Some(value) = self.buf_parse_one::<IanaType<Timestamp, String>>() {
                            param_values.push(VCardParameter::new(param_name, value));
                        }
                    }
                    VCardParameterName::Derived => {
                        if let Some(value) = self.buf_parse_one::<IanaType<Boolean, String>>() {
                            param_values.push(VCardParameter::new(param_name, value));
                        }
                    }
                    VCardParameterName::Type => {
                        for token in self.token_buf.drain(..) {
                            token.into_vcard_types(param_values);
                        }
                    }
                    VCardParameterName::Jscomps => {
                        if let Some(text) = self.raw_token() {
                            param_values.push(VCardParameter::jscomps(
                                VCardParameterValue::Jscomps(Jscomp::parse_list(&text)),
                            ));
                        }
                        self.token_buf.clear();
                    }
                    _ => {
                        param_values.extend(self.token_buf.drain(..).map(|token| {
                            VCardParameter::new(
                                param_name.clone(),
                                VCardParameterValue::Text(token.into_string()),
                            )
                        }));
                    }
                }
            } else if !param_name.is_empty() {
                match VCardType::parse(param_name) {
                    Some(typ) if self.token_buf.is_empty() => {
                        param_values.push(VCardParameter::typ(VCardParameterValue::Type(typ)));
                    }
                    _ => match param_name.first() {
                        Some(b'c' | b'C') if param_name.eq_ignore_ascii_case(b"charset") => {
                            if let Some(token) = self.token_buf.drain(..).next_back() {
                                params.charset = token.into_string().into();
                            }
                        }
                        Some(b'e' | b'E') if param_name.eq_ignore_ascii_case(b"encoding") => {
                            if let Some(token) = self.token_buf.drain(..).next_back() {
                                params.encoding = Encoding::parse(token.text.as_ref());
                            }
                        }
                        _ => {
                            if params.encoding.is_none()
                                && param_name.eq_ignore_ascii_case(b"base64")
                            {
                                params.encoding = Some(Encoding::Base64);
                            } else {
                                let name = VCardParameterName::Other(name_token.into_string());
                                let mut tokens = self.token_buf.drain(..);
                                match tokens.next_back() {
                                    Some(last) => {
                                        param_values.extend(tokens.map(|token| {
                                            VCardParameter::new(
                                                name.clone(),
                                                VCardParameterValue::Text(token.into_string()),
                                            )
                                        }));
                                        param_values.push(VCardParameter::new(
                                            name,
                                            VCardParameterValue::Text(last.into_string()),
                                        ));
                                    }
                                    None => param_values
                                        .push(VCardParameter::new(name, VCardParameterValue::Null)),
                                }
                            }
                        }
                    },
                }
            }
        }
    }
}

impl VCardValue {
    fn extend_component(&mut self, item: String) -> Option<String> {
        match self {
            VCardValue::Component(items) => items.push(item),
            VCardValue::Text(text) => *self = VCardValue::Component(vec![take(text), item]),
            _ => return Some(item),
        }
        None
    }
}

impl VCardParameter {
    fn type_list(text: &str) -> impl Iterator<Item = VCardParameter> + '_ {
        text.split(',')
            .map(str::trim)
            .filter(|text| !text.is_empty())
            .map(|text| {
                VCardParameter::typ(match VCardType::parse(text.as_bytes()) {
                    Some(typ) => VCardParameterValue::Type(typ),
                    None => VCardParameterValue::Text(text.to_string()),
                })
            })
    }
}

impl Jscomp {
    fn parse_list(text: &str) -> Vec<Jscomp> {
        let mut jscomps = Vec::with_capacity(4);
        for (item_pos, item) in text.split(';').enumerate() {
            if let Some(item) = item.strip_prefix("s,") {
                let mut sep = String::with_capacity(item.len());
                let mut last_is_escape = false;

                for ch in item.chars() {
                    if ch == '\\' && !last_is_escape {
                        last_is_escape = true;
                        continue;
                    }
                    last_is_escape = false;
                    sep.push(ch);
                }

                jscomps.push(Jscomp::Separator(sep));
            } else if item_pos != 0 {
                let mut position = None;
                let mut value = None;

                for (pos, item) in item.split(',').enumerate() {
                    if pos == 0 {
                        position = item.parse::<u32>().ok();
                    } else if pos == 1 {
                        value = item.parse::<u32>().ok();
                    }
                }

                if let Some(position) = position {
                    jscomps.push(Jscomp::Entry {
                        position,
                        value: value.unwrap_or_default(),
                    });
                }
            } else {
                jscomps.push(Jscomp::Separator(item.to_string()));
            }
        }
        jscomps
    }
}

impl Token<'_> {
    fn into_vcard_types(self, param_values: &mut Vec<VCardParameter>) {
        if let Some(typ) = VCardType::parse(self.text.as_ref()) {
            param_values.push(VCardParameter::typ(VCardParameterValue::Type(typ)));
        } else if !self.text.contains(&b',') {
            param_values.push(VCardParameter::typ(VCardParameterValue::Text(
                self.into_string(),
            )));
        } else {
            param_values.extend(VCardParameter::type_list(self.text.as_str()));
        }
    }

    fn into_vcard_value(self, value_type: VCardValueType, is_v4: bool) -> VCardValue {
        match value_type {
            VCardValueType::Date if is_v4 => self
                .into_vcard_date()
                .map(VCardValue::PartialDateTime)
                .unwrap_or_else(VCardValue::Text),
            VCardValueType::DateAndOrTime if is_v4 => self
                .into_vcard_date_and_or_datetime()
                .map(VCardValue::PartialDateTime)
                .unwrap_or_else(VCardValue::Text),
            VCardValueType::DateTime if is_v4 => self
                .into_vcard_date_time()
                .map(VCardValue::PartialDateTime)
                .unwrap_or_else(VCardValue::Text),
            VCardValueType::Time if is_v4 => self
                .into_vcard_time()
                .map(VCardValue::PartialDateTime)
                .unwrap_or_else(VCardValue::Text),
            VCardValueType::Timestamp if is_v4 => self
                .into_timestamp(true)
                .map(VCardValue::PartialDateTime)
                .unwrap_or_else(VCardValue::Text),
            VCardValueType::UtcOffset if is_v4 => self
                .into_offset()
                .map(VCardValue::PartialDateTime)
                .unwrap_or_else(VCardValue::Text),
            VCardValueType::Boolean => VCardValue::Boolean(self.into_boolean()),
            VCardValueType::Float => self
                .into_float()
                .map(VCardValue::Float)
                .unwrap_or_else(VCardValue::Text),
            VCardValueType::Integer => self
                .into_integer()
                .map(VCardValue::Integer)
                .unwrap_or_else(VCardValue::Text),
            VCardValueType::LanguageTag | VCardValueType::Text => {
                VCardValue::Text(self.into_string())
            }
            VCardValueType::Uri => self
                .into_uri_bytes()
                .map(|data| VCardValue::Binary(Box::new(data)))
                .unwrap_or_else(VCardValue::Text),
            VCardValueType::Date
            | VCardValueType::DateAndOrTime
            | VCardValueType::DateTime
            | VCardValueType::Time => self
                .into_vcard_datetime_or_legacy()
                .map(VCardValue::PartialDateTime)
                .unwrap_or_else(VCardValue::Text),
            VCardValueType::Timestamp => self
                .into_vcard_timestamp_or_legacy()
                .map(VCardValue::PartialDateTime)
                .unwrap_or_else(VCardValue::Text),
            VCardValueType::UtcOffset => self
                .into_vcard_offset_or_legacy()
                .map(VCardValue::PartialDateTime)
                .unwrap_or_else(VCardValue::Text),
        }
    }

    pub(crate) fn into_vcard_date(self) -> std::result::Result<PartialDateTime, String> {
        let mut dt = PartialDateTime::default();
        dt.parse_vcard_date(&mut self.text.iter().peekable());
        if !dt.is_null() {
            Ok(dt)
        } else {
            Err(self.into_string())
        }
    }

    pub(crate) fn into_vcard_date_and_or_datetime(
        self,
    ) -> std::result::Result<PartialDateTime, String> {
        let mut dt = PartialDateTime::default();
        dt.parse_vcard_date_and_or_time(&mut self.text.iter().peekable());
        if !dt.is_null() {
            Ok(dt)
        } else {
            Err(self.into_string())
        }
    }

    pub(crate) fn into_vcard_date_time(self) -> std::result::Result<PartialDateTime, String> {
        let mut dt = PartialDateTime::default();
        dt.parse_vcard_date_time(&mut self.text.iter().peekable());
        if !dt.is_null() {
            Ok(dt)
        } else {
            Err(self.into_string())
        }
    }

    pub(crate) fn into_vcard_time(self) -> std::result::Result<PartialDateTime, String> {
        let mut dt = PartialDateTime::default();
        dt.parse_vcard_time(&mut self.text.iter().peekable(), false);
        if !dt.is_null() {
            Ok(dt)
        } else {
            Err(self.into_string())
        }
    }

    pub(crate) fn into_vcard_timestamp_or_legacy(
        self,
    ) -> std::result::Result<PartialDateTime, String> {
        let mut dt = PartialDateTime::default();
        if dt.parse_timestamp(&mut self.text.iter().peekable(), false) {
            Ok(dt)
        } else {
            let mut dt = PartialDateTime::default();
            if dt.parse_vcard_date_legacy(&mut self.text.iter().peekable()) {
                Ok(dt)
            } else {
                Err(self.into_string())
            }
        }
    }

    pub(crate) fn into_vcard_datetime_or_legacy(
        self,
    ) -> std::result::Result<PartialDateTime, String> {
        let mut dt = PartialDateTime::default();
        if dt.parse_vcard_date_legacy(&mut self.text.iter().peekable()) {
            Ok(dt)
        } else {
            self.into_vcard_date_and_or_datetime()
        }
    }

    pub(crate) fn into_vcard_offset_or_legacy(
        self,
    ) -> std::result::Result<PartialDateTime, String> {
        let mut dt = PartialDateTime::default();
        if dt.parse_vcard_zone_legacy(&mut self.text.iter().peekable()) {
            Ok(dt)
        } else {
            self.into_offset()
        }
    }
}

impl PartialDateTime {
    pub fn parse_vcard_date_legacy(&mut self, iter: &mut Peekable<Iter<'_, u8>>) -> bool {
        let mut idx = 0;

        for ch in iter {
            match ch {
                b'0'..=b'9' => {
                    let value = match idx {
                        0 => {
                            if let Some(value) = &mut self.year {
                                *value =
                                    value.saturating_mul(10).saturating_add((ch - b'0') as u16);
                            } else {
                                self.year = Some((ch - b'0') as u16);
                            }
                            continue;
                        }
                        1 => &mut self.month,
                        2 => &mut self.day,
                        3 => &mut self.hour,
                        4 => &mut self.minute,
                        5 => &mut self.second,
                        6 => &mut self.tz_hour,
                        7 => &mut self.tz_minute,
                        _ => return false,
                    };

                    if let Some(value) = value {
                        *value = value.saturating_mul(10).saturating_add(ch - b'0');
                    } else {
                        *value = Some(ch - b'0');
                    }
                }
                b'T' | b't' if idx < 3 => {
                    idx = 3;
                }
                b'+' if idx <= 5 => {
                    idx = 6;
                }
                b'Z' | b'z' if idx == 5 => {
                    self.tz_hour = Some(0);
                    self.tz_minute = Some(0);
                    break;
                }
                b'-' if idx <= 2 => {
                    idx += 1;
                }
                b'-' if idx <= 5 => {
                    self.tz_minus = true;
                    idx = 6;
                }
                b':' if (3..=6).contains(&idx) => {
                    idx += 1;
                }
                b' ' | b'\t' | b'\r' | b'\n' => {
                    continue;
                }
                _ => return false,
            }
        }

        self.has_date() || self.has_zone()
    }

    pub fn parse_vcard_zone_legacy(&mut self, iter: &mut Peekable<Iter<'_, u8>>) -> bool {
        let mut idx = 0;

        for ch in iter {
            match ch {
                b'0'..=b'9' => {
                    let value = match idx {
                        0 => &mut self.tz_hour,
                        1 => &mut self.tz_minute,
                        _ => return false,
                    };

                    if let Some(value) = value {
                        *value = value.saturating_mul(10).saturating_add(ch - b'0');
                    } else {
                        *value = Some(ch - b'0');
                    }
                }
                b'+' if self.tz_hour.is_none() => {}
                b'-' if self.tz_hour.is_none() => {
                    self.tz_minus = true;
                }
                b'Z' | b'z' if self.tz_hour.is_none() => {
                    self.tz_hour = Some(0);
                    self.tz_minute = Some(0);
                    break;
                }
                b':' => {
                    idx += 1;
                }
                b' ' | b'\t' | b'\r' | b'\n' => {
                    continue;
                }
                _ => return false,
            }
        }

        self.tz_hour.is_some() && self.tz_minute.is_some()
    }

    pub fn parse_vcard_date_time(&mut self, iter: &mut Peekable<Iter<'_, u8>>) {
        self.parse_vcard_date_noreduc(iter);
        if matches!(iter.peek(), Some(&&b'T' | &&b't')) {
            iter.next();
            self.parse_vcard_time(iter, true);
        }
    }

    pub fn parse_vcard_date_and_or_time(&mut self, iter: &mut Peekable<Iter<'_, u8>>) {
        self.parse_vcard_date(iter);
        if matches!(iter.peek(), Some(&&b'T' | &&b't')) {
            iter.next();
            self.parse_vcard_time(iter, false);
        }
    }

    pub fn parse_vcard_date(&mut self, iter: &mut Peekable<Iter<'_, u8>>) {
        parse_digits(iter, &mut self.year, 4, true);
        if self.year.is_some() && iter.peek() == Some(&&b'-') {
            iter.next();
            parse_small_digits(iter, &mut self.month, 2, true);
        } else {
            parse_small_digits(iter, &mut self.month, 2, true);
            if self.year.is_none() && self.month.is_some() && iter.peek() == Some(&&b'-') {
                iter.next();
            }
            parse_small_digits(iter, &mut self.day, 2, false);
        }
    }

    pub fn parse_vcard_date_noreduc(&mut self, iter: &mut Peekable<Iter<'_, u8>>) {
        parse_digits(iter, &mut self.year, 4, true);
        parse_small_digits(iter, &mut self.month, 2, true);
        parse_small_digits(iter, &mut self.day, 2, false);
    }

    pub fn parse_vcard_time(&mut self, iter: &mut Peekable<Iter<'_, u8>>, mut notrunc: bool) {
        for part in [&mut self.hour, &mut self.minute, &mut self.second] {
            match iter.peek() {
                Some(b'0'..=b'9') => {
                    notrunc = true;
                    parse_small_digits(iter, part, 2, false);
                }
                Some(b'-') if !notrunc => {
                    iter.next();
                }
                _ => break,
            }
        }
        self.parse_zone(iter);
    }
}

#[cfg(all(test, stalwart_tests))]
#[rustfmt::skip]
#[path = "../../../../../stalwart-tests/unit/calcard/src/vcard/parser/tests.rs"]
mod tests;
