/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

mod budget;

use ammonia::{Builder, Url};
use budget::{MAX_RECONSTRUCTION_COST, reconstruction_cost, text_fallback};
use memchr::memmem;
use std::borrow::Cow;

const TAGS: &[&str] = &[
    "a",
    "abbr",
    "acronym",
    "address",
    "area",
    "b",
    "bdi",
    "bdo",
    "big",
    "blockquote",
    "br",
    "caption",
    "center",
    "cite",
    "code",
    "col",
    "colgroup",
    "dd",
    "del",
    "dfn",
    "div",
    "dl",
    "dt",
    "em",
    "font",
    "h1",
    "h2",
    "h3",
    "h4",
    "h5",
    "h6",
    "hr",
    "i",
    "img",
    "ins",
    "kbd",
    "li",
    "map",
    "mark",
    "ol",
    "p",
    "pre",
    "q",
    "s",
    "samp",
    "small",
    "span",
    "strike",
    "strong",
    "sub",
    "sup",
    "table",
    "tbody",
    "td",
    "tfoot",
    "th",
    "thead",
    "tr",
    "tt",
    "u",
    "ul",
    "var",
    "wbr",
];

macro_rules! dropped_with_content {
    ($($tag:literal),* $(,)?) => {
        const DROPPED_WITH_CONTENT: &[&str] = &[$($tag),*];

        fn is_dropped_with_content(name: &str) -> bool {
            hashify::set!(name.as_bytes(), $($tag),*)
        }
    };
}

dropped_with_content!(
    "applet",
    "frameset",
    "iframe",
    "math",
    "noembed",
    "noframes",
    "noscript",
    "object",
    "plaintext",
    "script",
    "select",
    "style",
    "svg",
    "template",
    "textarea",
    "title",
    "xmp",
);

const GENERIC_ATTRIBUTES: &[&str] = &[
    "align",
    "bgcolor",
    "border",
    "cellpadding",
    "cellspacing",
    "class",
    "color",
    "dir",
    "height",
    "hspace",
    "lang",
    "nowrap",
    "style",
    "title",
    "valign",
    "vspace",
    "width",
];

const TAG_ATTRIBUTES: &[(&str, &[&str])] = &[
    ("a", &["href", "name"]),
    ("area", &["alt", "coords", "href", "shape"]),
    ("col", &["span"]),
    ("colgroup", &["span"]),
    ("font", &["face", "size"]),
    ("img", &["alt", "src"]),
    ("li", &["type", "value"]),
    ("map", &["name"]),
    ("ol", &["start", "type"]),
    ("table", &["summary"]),
    ("td", &["abbr", "colspan", "headers", "rowspan", "scope"]),
    ("th", &["abbr", "colspan", "headers", "rowspan", "scope"]),
    ("ul", &["type"]),
];

const URL_SCHEMES: &[&str] = &["cid", "data", "ftp", "http", "https", "mailto", "tel"];

const STYLE_PROPERTIES: &[&str] = &[
    "background-color",
    "border",
    "border-bottom",
    "border-bottom-color",
    "border-bottom-style",
    "border-bottom-width",
    "border-collapse",
    "border-color",
    "border-left",
    "border-left-color",
    "border-left-style",
    "border-left-width",
    "border-radius",
    "border-right",
    "border-right-color",
    "border-right-style",
    "border-right-width",
    "border-spacing",
    "border-style",
    "border-top",
    "border-top-color",
    "border-top-style",
    "border-top-width",
    "border-width",
    "clear",
    "color",
    "direction",
    "display",
    "float",
    "font",
    "font-family",
    "font-size",
    "font-style",
    "font-variant",
    "font-weight",
    "height",
    "letter-spacing",
    "line-height",
    "list-style-type",
    "margin",
    "margin-bottom",
    "margin-left",
    "margin-right",
    "margin-top",
    "max-height",
    "max-width",
    "min-height",
    "min-width",
    "padding",
    "padding-bottom",
    "padding-left",
    "padding-right",
    "padding-top",
    "table-layout",
    "text-align",
    "text-decoration",
    "text-indent",
    "text-transform",
    "vertical-align",
    "white-space",
    "width",
    "word-spacing",
];

const UNSAFE_STYLE: &[&str] = &["expression", "url(", "\\", "behavior", "binding"];

pub struct HtmlFilter(Builder<'static>);

impl HtmlFilter {
    pub fn new() -> Self {
        let mut builder = Builder::empty();
        builder
            .tags(TAGS.iter().copied().collect())
            .clean_content_tags(DROPPED_WITH_CONTENT.iter().copied().collect())
            .generic_attributes(GENERIC_ATTRIBUTES.iter().copied().collect())
            .tag_attributes(
                TAG_ATTRIBUTES
                    .iter()
                    .map(|(tag, attributes)| (*tag, attributes.iter().copied().collect()))
                    .collect(),
            )
            .url_schemes(URL_SCHEMES.iter().copied().collect())
            .filter_style_properties(STYLE_PROPERTIES.iter().copied().collect())
            .attribute_filter(filter_attribute);
        HtmlFilter(builder)
    }

    pub fn filter(&self, html: &str) -> String {
        if reconstruction_cost(html) > MAX_RECONSTRUCTION_COST {
            return text_fallback(html);
        }
        self.0.clean(html).to_string()
    }
}

impl Default for HtmlFilter {
    fn default() -> Self {
        Self::new()
    }
}

fn filter_attribute<'v>(element: &str, attribute: &str, value: &'v str) -> Option<Cow<'v, str>> {
    let keep = hashify::fnc_map!(attribute.as_bytes(),
        "style" => return safe_style(value),
        "href" => accepts_data_url(value, |_| false),
        "src" => accepts_data_url(value, |path| element == "img" && is_raster_data(path)),
        _ => true,
    );
    keep.then_some(Cow::Borrowed(value))
}

fn safe_style(value: &str) -> Option<Cow<'_, str>> {
    let is_safe = |declaration: &str| {
        !UNSAFE_STYLE
            .iter()
            .any(|needle| contains_ignore_case(declaration, needle))
            && is_ascii_outside_strings(declaration.as_bytes())
    };
    if is_safe(value) {
        return Some(Cow::Borrowed(value));
    }
    let mut out = String::with_capacity(value.len());
    for declaration in value.split(';').filter(|declaration| is_safe(declaration)) {
        if !out.is_empty() {
            out.push(';');
        }
        out.push_str(declaration);
    }
    (!out.trim().is_empty()).then_some(Cow::Owned(out))
}

fn is_ascii_outside_strings(mut rest: &[u8]) -> bool {
    loop {
        let after = match rest {
            [] => return true,
            [quote @ (b'"' | b'\''), tail @ ..] => tail
                .split_inclusive(|byte| byte == quote || matches!(byte, b'\n' | b'\r' | 0x0c))
                .next()
                .filter(|string| string.last() == Some(quote))
                .and_then(|string| tail.get(string.len()..)),
            [b'/', b'*', tail @ ..] => {
                memmem::find(tail, b"*/").and_then(|end| tail.get(end + 2..))
            }
            [byte, tail @ ..] if byte.is_ascii() => Some(tail),
            _ => None,
        };
        let Some(after) = after else {
            return false;
        };
        rest = after;
    }
}

fn accepts_data_url(value: &str, accept: impl Fn(&str) -> bool) -> bool {
    match Url::parse(value) {
        Ok(url) if url.scheme() == "data" => accept(url.path()),
        _ => true,
    }
}

fn is_raster_data(path: &str) -> bool {
    path.split([';', ',']).next().is_some_and(|media_type| {
        hashify::set_ignore_case!(
            media_type.as_bytes(),
            "image/png",
            "image/gif",
            "image/jpeg",
            "image/jpg",
            "image/webp",
            "image/bmp",
        )
    })
}

fn contains_ignore_case(value: &str, needle: &str) -> bool {
    value
        .as_bytes()
        .windows(needle.len())
        .any(|window| window.eq_ignore_ascii_case(needle.as_bytes()))
}

#[cfg(all(test, stalwart_tests))]
#[rustfmt::skip]
#[path = "../../../../../stalwart-tests/unit/exchange-proto/src/ews/html/tests.rs"]
mod tests;
