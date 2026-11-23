/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{
    envelope::{EnvelopeWriter, SOAP, XmlDecl},
    responses::MessageXml,
    schema::ResponseCode,
    types::value::T,
    version::ServerVersionInfo,
};
use crate::xml::Ns;
use std::borrow::Cow;

const ERRORS: &str = "e";
const NO_PREFIX: &str = "";
const FAULT_LANG: &str = "en-US";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Fault<'x> {
    pub code: ResponseCode,
    pub text: Cow<'x, str>,
    pub line: Option<(u32, u32)>,
    pub message_xml: Option<MessageXml<'x>>,
}

impl Fault<'_> {
    pub const HTTP_STATUS: u16 = 500;
}

pub fn write_fault(out: &mut Vec<u8>, version: &ServerVersionInfo, fault: &Fault<'_>) {
    let mut envelope = EnvelopeWriter::begin(out, version, XmlDecl::Emit);
    let w = envelope.writer();
    let code = fault.code.as_str();
    w.start(SOAP, "Fault");
    w.start(NO_PREFIX, "faultcode").close_start();
    w.raw(T.as_bytes());
    w.raw(b":");
    w.text(code);
    w.end(NO_PREFIX, "faultcode");
    w.start(NO_PREFIX, "faultstring")
        .attr("xml:lang", FAULT_LANG)
        .close_start();
    w.text(&fault.text);
    w.end(NO_PREFIX, "faultstring");
    w.start(NO_PREFIX, "detail")
        .ns_decl(ERRORS, Ns::Errors.uri());
    w.leaf(ERRORS, "ResponseCode", code);
    w.leaf(ERRORS, "Message", &fault.text);
    if fault.line.is_some() || fault.message_xml.is_some() {
        w.start(T, "MessageXml");
        if let Some((line, column)) = fault.line {
            w.leaf_u64(T, "LineNumber", u64::from(line));
            w.leaf_u64(T, "LinePosition", u64::from(column));
        }
        if let Some(message_xml) = &fault.message_xml {
            message_xml.write_children(w);
        }
        w.end(T, "MessageXml");
    }
    w.end(NO_PREFIX, "detail");
    w.end(SOAP, "Fault");
    envelope.finish();
}
