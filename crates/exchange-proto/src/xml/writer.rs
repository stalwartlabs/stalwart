/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::common::{
    Base64Encoder, Precision, UtcSeconds, XsForm,
    base64::{base64_encode_into, base64_encoded_len},
    xml::{escape_attr, escape_text},
};

pub const XML_DECL: &str = "<?xml version=\"1.0\" encoding=\"utf-8\"?>";

const BASE64_TAIL_RESERVE: usize = 4096;

pub trait XmlWrite {
    fn write(&self, w: &mut XmlWriter<'_>);
}

pub struct XmlWriter<'o> {
    out: &'o mut Vec<u8>,
    open: bool,
    millis: bool,
}

impl<'o> XmlWriter<'o> {
    pub fn new(out: &'o mut Vec<u8>) -> Self {
        XmlWriter {
            out,
            open: false,
            millis: false,
        }
    }

    pub fn set_millis(&mut self, millis: bool) {
        self.millis = millis;
    }

    pub fn millis(&self) -> bool {
        self.millis
    }

    pub fn buffer(&mut self) -> &mut Vec<u8> {
        self.close_start();
        self.out
    }

    pub fn len(&self) -> usize {
        self.out.len()
    }

    pub fn is_empty(&self) -> bool {
        self.out.is_empty()
    }

    pub fn decl(&mut self) {
        self.out.extend_from_slice(XML_DECL.as_bytes());
    }

    pub fn start(&mut self, prefix: &str, local: &str) -> &mut Self {
        self.close_start();
        self.out.push(b'<');
        self.name(prefix, local);
        self.open = true;
        self
    }

    pub fn attr(&mut self, name: &str, value: &str) -> &mut Self {
        self.out.push(b' ');
        self.out.extend_from_slice(name.as_bytes());
        self.out.extend_from_slice(b"=\"");
        escape_attr(value, self.out);
        self.out.push(b'"');
        self
    }

    pub fn attr_opt(&mut self, name: &str, value: Option<&str>) -> &mut Self {
        if let Some(value) = value {
            self.attr(name, value);
        }
        self
    }

    pub fn attr_u64(&mut self, name: &str, value: u64) -> &mut Self {
        self.attr_raw_start(name);
        push_u64(self.out, value);
        self.out.push(b'"');
        self
    }

    pub fn attr_i64(&mut self, name: &str, value: i64) -> &mut Self {
        self.attr_raw_start(name);
        push_i64(self.out, value);
        self.out.push(b'"');
        self
    }

    pub fn attr_bool(&mut self, name: &str, value: bool) -> &mut Self {
        self.attr(name, bool_str(value))
    }

    pub fn attr_datetime(
        &mut self,
        name: &str,
        value: UtcSeconds,
        precision: Precision,
        form: XsForm,
    ) -> &mut Self {
        self.attr_raw_start(name);
        value.write_xs_form(self.out, precision, form);
        self.out.push(b'"');
        self
    }

    pub fn ns_decl(&mut self, prefix: &str, uri: &str) -> &mut Self {
        self.out.extend_from_slice(b" xmlns");
        if !prefix.is_empty() {
            self.out.push(b':');
            self.out.extend_from_slice(prefix.as_bytes());
        }
        self.out.extend_from_slice(b"=\"");
        self.out.extend_from_slice(uri.as_bytes());
        self.out.push(b'"');
        self
    }

    pub fn close_start(&mut self) {
        if self.open {
            self.out.push(b'>');
            self.open = false;
        }
    }

    pub fn empty(&mut self) {
        if self.open {
            self.out.extend_from_slice(b"/>");
            self.open = false;
        }
    }

    pub fn text(&mut self, s: &str) {
        self.close_start();
        escape_text(s, self.out);
    }

    pub fn raw(&mut self, s: &[u8]) {
        self.close_start();
        self.out.extend_from_slice(s);
    }

    pub fn text_u64(&mut self, value: u64) {
        self.close_start();
        push_u64(self.out, value);
    }

    pub fn text_i64(&mut self, value: i64) {
        self.close_start();
        push_i64(self.out, value);
    }

    pub fn text_datetime(&mut self, value: UtcSeconds, precision: Precision, form: XsForm) {
        self.close_start();
        value.write_xs_form(self.out, precision, form);
    }

    pub fn base64(&mut self, src: &[u8]) {
        self.close_start();
        self.out
            .reserve(base64_encoded_len(src.len()).saturating_add(BASE64_TAIL_RESERVE));
        base64_encode_into(src, self.out);
    }

    pub fn base64_stream(&mut self) -> Base64Sink<'_, 'o> {
        self.close_start();
        Base64Sink {
            w: self,
            encoder: Base64Encoder::new(),
        }
    }

    pub fn end(&mut self, prefix: &str, local: &str) {
        if self.open {
            self.out.extend_from_slice(b"/>");
            self.open = false;
        } else {
            self.out.extend_from_slice(b"</");
            self.name(prefix, local);
            self.out.push(b'>');
        }
    }

    pub fn leaf(&mut self, prefix: &str, local: &str, text: &str) {
        self.start(prefix, local);
        self.close_start();
        escape_text(text, self.out);
        self.end_closed(prefix, local);
    }

    pub fn leaf_u64(&mut self, prefix: &str, local: &str, value: u64) {
        self.start(prefix, local).close_start();
        push_u64(self.out, value);
        self.end_closed(prefix, local);
    }

    pub fn leaf_i64(&mut self, prefix: &str, local: &str, value: i64) {
        self.start(prefix, local).close_start();
        push_i64(self.out, value);
        self.end_closed(prefix, local);
    }

    pub fn leaf_bool(&mut self, prefix: &str, local: &str, value: bool) {
        self.leaf(prefix, local, bool_str(value));
    }

    pub fn leaf_datetime(
        &mut self,
        prefix: &str,
        local: &str,
        value: UtcSeconds,
        precision: Precision,
    ) {
        self.start(prefix, local).close_start();
        value.write_xs(self.out, precision);
        self.end_closed(prefix, local);
    }

    pub fn empty_leaf(&mut self, prefix: &str, local: &str) {
        self.start(prefix, local);
        self.empty();
    }

    fn end_closed(&mut self, prefix: &str, local: &str) {
        self.out.extend_from_slice(b"</");
        self.name(prefix, local);
        self.out.push(b'>');
    }

    fn name(&mut self, prefix: &str, local: &str) {
        if !prefix.is_empty() {
            self.out.extend_from_slice(prefix.as_bytes());
            self.out.push(b':');
        }
        self.out.extend_from_slice(local.as_bytes());
    }

    fn attr_raw_start(&mut self, name: &str) {
        self.out.push(b' ');
        self.out.extend_from_slice(name.as_bytes());
        self.out.extend_from_slice(b"=\"");
    }
}

impl std::fmt::Write for XmlWriter<'_> {
    fn write_str(&mut self, s: &str) -> std::fmt::Result {
        self.text(s);
        Ok(())
    }
}

pub struct Base64Sink<'w, 'o> {
    w: &'w mut XmlWriter<'o>,
    encoder: Base64Encoder,
}

impl Base64Sink<'_, '_> {
    pub fn push(&mut self, src: &[u8]) {
        self.encoder.push(src, self.w.out);
    }

    pub fn finish(self) {
        self.encoder.finish(self.w.out);
    }
}

pub const fn bool_str(value: bool) -> &'static str {
    if value { "true" } else { "false" }
}

pub fn push_u64(out: &mut Vec<u8>, mut value: u64) {
    let mut buf = [0u8; 20];
    let mut pos = buf.len();
    for slot in buf.iter_mut().rev() {
        *slot = b'0' + (value % 10) as u8;
        value /= 10;
        pos -= 1;
        if value == 0 {
            break;
        }
    }
    out.extend_from_slice(buf.get(pos..).unwrap_or_default());
}

pub fn push_i64(out: &mut Vec<u8>, value: i64) {
    if value < 0 {
        out.push(b'-');
    }
    push_u64(out, value.unsigned_abs());
}
