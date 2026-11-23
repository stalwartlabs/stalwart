/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::borrow::Cow;

use mail_parser::{html_to_text, text_to_html};

use crate::{
    convert::{
        ConvertError, code_page_charset,
        model::{MessageContent, PropBag},
        rtf::{Deencapsulated, rtf_decompress, rtf_deencapsulate, rtf_to_plain},
        tags::{self, native_body},
    },
    mapi::prop::{OwnedPropValue, PropKey, PropType},
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BodyKindRequest {
    Text,
    Html,
    Rtf,
    Native,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BodySelection<'c> {
    Text(Cow<'c, str>),
    Html(Cow<'c, str>),
    Rtf(&'c [u8]),
}

pub fn select_body(content: &MessageContent, want: BodyKindRequest) -> Option<BodySelection<'_>> {
    let bodies = Bodies::new(&content.props);
    match want {
        BodyKindRequest::Text => bodies.text_selection(),
        BodyKindRequest::Html => bodies.html_selection(),
        BodyKindRequest::Rtf => match bodies.rtf {
            Some(rtf) => Some(BodySelection::Rtf(rtf)),
            None => bodies.html_selection(),
        },
        BodyKindRequest::Native => match bodies.native {
            Some(native_body::PLAIN) => bodies.text_selection(),
            Some(native_body::RTF) => match bodies.rtf {
                Some(rtf) => Some(BodySelection::Rtf(rtf)),
                None => bodies.html_selection(),
            },
            Some(native_body::HTML) => bodies.html_selection(),
            _ if bodies.has_html() => bodies.html_selection(),
            _ => match bodies.rtf {
                Some(rtf) => Some(BodySelection::Rtf(rtf)),
                None => bodies.text_selection(),
            },
        },
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BodySource {
    Html,
    Rtf,
}

pub(super) type BodyPair = (Option<Cow<'static, str>>, Option<Cow<'static, str>>);

pub fn source_text(
    props: &PropBag,
    source: BodySource,
    max_decoded: u32,
) -> Result<Option<Cow<'_, str>>, ConvertError> {
    let bodies = Bodies::new(props);
    Ok(match source {
        BodySource::Html => bodies.html().map(|html| Cow::Owned(html_to_text(&html))),
        BodySource::Rtf => match bodies.rtf {
            Some(rtf) => match decode_rtf(rtf, max_decoded)? {
                (Some(text), _) => Some(text),
                (None, html) => html.map(|html| Cow::Owned(html_to_text(&html))),
            },
            None => None,
        },
    })
}

pub(super) fn decode_rtf(rtf: &[u8], max_decoded: u32) -> Result<BodyPair, ConvertError> {
    let mut decompressed = Vec::new();
    rtf_decompress(rtf, &mut decompressed, max_decoded)?;
    let mut out = Vec::new();
    Ok(match rtf_deencapsulate(&decompressed, &mut out) {
        Some(Deencapsulated::Html) => (None, Some(Cow::Owned(lossy_text(out)))),
        Some(Deencapsulated::Text) => (Some(Cow::Owned(lossy_text(out))), None),
        None => {
            let mut plain = String::new();
            rtf_to_plain(&decompressed, &mut plain);
            (Some(Cow::Owned(plain)), None)
        }
    })
}

fn lossy_text(bytes: Vec<u8>) -> String {
    String::from_utf8(bytes)
        .unwrap_or_else(|err| String::from_utf8_lossy(err.as_bytes()).into_owned())
}

#[derive(Clone, Copy)]
enum StoredHtml<'c> {
    Bytes {
        bytes: &'c [u8],
        code_page: Option<u16>,
    },
    Text(&'c str),
}

pub(super) struct Bodies<'c> {
    pub text: Option<&'c str>,
    pub rtf: Option<&'c [u8]>,
    html: Option<StoredHtml<'c>>,
    native: Option<i32>,
}

impl<'c> Bodies<'c> {
    pub fn new(props: &'c PropBag) -> Self {
        let key = |id| PropKey::tag(id);
        let text = match props.get(key(tags::BODY).as_ref(), PropType::Unicode) {
            Some(OwnedPropValue::Unicode(text)) => Some(&**text),
            _ => None,
        };
        let html = match props.get(key(tags::HTML).as_ref(), PropType::Binary) {
            Some(OwnedPropValue::Binary(bytes)) => {
                let code_page =
                    match props.get(key(tags::INTERNET_CODEPAGE).as_ref(), PropType::I32) {
                        Some(OwnedPropValue::I32(code_page)) => u16::try_from(*code_page).ok(),
                        _ => None,
                    };
                Some(StoredHtml::Bytes { bytes, code_page })
            }
            _ => match props.get(key(tags::HTML).as_ref(), PropType::Unicode) {
                Some(OwnedPropValue::Unicode(html)) => Some(StoredHtml::Text(html)),
                _ => None,
            },
        };
        let rtf = match props.get(key(tags::RTF_COMPRESSED).as_ref(), PropType::Binary) {
            Some(OwnedPropValue::Binary(rtf)) => Some(&rtf[..]),
            _ => None,
        };
        let native = match props.get(key(tags::NATIVE_BODY).as_ref(), PropType::I32) {
            Some(OwnedPropValue::I32(native)) => Some(*native),
            _ => None,
        };
        Bodies {
            text,
            rtf,
            html,
            native,
        }
    }

    pub fn has_html(&self) -> bool {
        self.html.is_some()
    }

    pub fn html(&self) -> Option<Cow<'c, str>> {
        self.html.map(|html| match html {
            StoredHtml::Bytes { bytes, code_page } => decode_html(bytes, code_page),
            StoredHtml::Text(html) => Cow::Borrowed(html),
        })
    }

    fn text_selection(&self) -> Option<BodySelection<'c>> {
        if let Some(text) = self.text {
            Some(BodySelection::Text(Cow::Borrowed(text)))
        } else if let Some(html) = self.html() {
            Some(BodySelection::Text(Cow::Owned(html_to_text(&html))))
        } else {
            self.rtf.map(BodySelection::Rtf)
        }
    }

    fn html_selection(&self) -> Option<BodySelection<'c>> {
        if let Some(html) = self.html() {
            Some(BodySelection::Html(html))
        } else if let Some(text) = self.text {
            Some(BodySelection::Html(Cow::Owned(text_to_html(text))))
        } else {
            self.rtf.map(BodySelection::Rtf)
        }
    }
}

fn decode_html(bytes: &[u8], code_page: Option<u16>) -> Cow<'_, str> {
    match code_page {
        None | Some(65001) => String::from_utf8_lossy(bytes),
        Some(code_page) => code_page_charset(code_page).decode(bytes),
    }
}
