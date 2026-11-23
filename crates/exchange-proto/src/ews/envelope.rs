/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    ews::{
        header::SoapHeader,
        operation::Operation,
        parser::{EwsLimits, ParseError, ParseErrorKind, Parser},
        requests::EwsRequest,
        responses::{MessageResult, ResponseMessage, Status, message_element},
        types::value::{M, T},
        version::ServerVersionInfo,
    },
    xml::{Ns, XmlWrite, XmlWriter},
};

pub(crate) const SOAP: &str = "soap";

#[derive(Debug, Clone, PartialEq)]
pub struct Envelope<'a> {
    pub header: SoapHeader<'a>,
    pub request: EwsRequest<'a>,
    pub extra_body_children: u16,
}

pub fn parse_request<'a>(body: &'a [u8], limits: &EwsLimits) -> Result<Envelope<'a>, ParseError> {
    let mut p = Parser::new(body, limits);
    p.any_child()?
        .filter(|root| root.local == "Envelope" && root.ns == Ns::Soap11)
        .ok_or_else(|| p.error(ParseErrorKind::NotSoapEnvelope))?;
    let mut header = SoapHeader::default();
    let mut request = None;
    while let Some(child) = p.any_child()? {
        if child.ns != Ns::Soap11 {
            p.skip()?;
            continue;
        }
        match child.local {
            "Header" => header = SoapHeader::parse(&mut p)?,
            "Body" if request.is_none() => request = Some(parse_body(&mut p)?),
            _ => p.skip()?,
        }
    }
    let (request, extra_body_children) =
        request.ok_or_else(|| p.error(ParseErrorKind::MissingBody))?;
    p.finish()?;
    Ok(Envelope {
        header,
        request,
        extra_body_children,
    })
}

fn parse_body<'a>(p: &mut Parser<'a>) -> Result<(EwsRequest<'a>, u16), ParseError> {
    let child = p
        .any_child()?
        .ok_or_else(|| p.error(ParseErrorKind::MissingBody))?;
    p.expect_messages(&child)?;
    let op = Operation::from_request_root(child.local.as_bytes())
        .ok_or_else(|| p.error(ParseErrorKind::UnknownOperation))?;
    p.op = Some(op);
    let request = EwsRequest::parse(p, op, &child.attrs)?;
    let mut extra = 0u16;
    while p.any_child()?.is_some() {
        extra = extra.saturating_add(1);
        p.skip()?;
    }
    Ok((request, extra))
}

const STREAM_ROOT: &str = "";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum XmlDecl {
    Emit,
    Omit,
}

pub struct EnvelopeWriter<'o> {
    w: XmlWriter<'o>,
    root: &'static str,
}

impl<'o> EnvelopeWriter<'o> {
    pub fn begin(out: &'o mut Vec<u8>, version: &ServerVersionInfo, decl: XmlDecl) -> Self {
        Self::open(out, version, decl, SOAP)
    }

    pub fn begin_stream(out: &'o mut Vec<u8>, version: &ServerVersionInfo, decl: XmlDecl) -> Self {
        Self::open(out, version, decl, STREAM_ROOT)
    }

    fn open(
        out: &'o mut Vec<u8>,
        version: &ServerVersionInfo,
        decl: XmlDecl,
        root: &'static str,
    ) -> Self {
        let mut w = XmlWriter::new(out);
        if decl == XmlDecl::Emit {
            w.decl();
        }
        w.start(root, "Envelope");
        if root.is_empty() {
            w.ns_decl("", Ns::Soap11.uri());
        }
        w.ns_decl(SOAP, Ns::Soap11.uri())
            .ns_decl(M, Ns::Messages.uri())
            .ns_decl(T, Ns::Types.uri());
        w.start(SOAP, "Header");
        w.start(T, "ServerVersionInfo");
        version.write_attrs(&mut w);
        w.empty();
        w.end(SOAP, "Header");
        w.start(SOAP, "Body");
        EnvelopeWriter { w, root }
    }

    pub fn set_millis(&mut self, millis: bool) {
        self.w.set_millis(millis);
    }

    pub fn shape_a(mut self, op: Operation) -> MessagesWriter<'o> {
        let root = op.response_root();
        self.w.start(M, root);
        self.w.start(M, "ResponseMessages");
        MessagesWriter {
            w: self.w,
            op,
            root: self.root,
        }
    }

    pub fn shape_d(mut self, op: Operation, status: &Status<'_>) -> MessagesWriter<'o> {
        status.start(&mut self.w, op.response_root());
        self.w.start(M, "ResponseMessages");
        MessagesWriter {
            w: self.w,
            op,
            root: self.root,
        }
    }

    pub fn shape_b(mut self, op: Operation, status: &Status<'_>) -> BodyWriter<'o> {
        status.start(&mut self.w, op.response_root());
        BodyWriter {
            w: self.w,
            op,
            root: self.root,
        }
    }

    pub fn body<B: XmlWrite>(mut self, body: &B) {
        body.write(&mut self.w);
        close_envelope(&mut self.w, self.root);
    }

    pub(crate) fn writer(&mut self) -> &mut XmlWriter<'o> {
        &mut self.w
    }

    pub(crate) fn finish(mut self) {
        close_envelope(&mut self.w, self.root);
    }
}

fn close_envelope(w: &mut XmlWriter<'_>, root: &str) {
    w.end(SOAP, "Body");
    w.end(root, "Envelope");
}

pub struct BodyWriter<'o> {
    w: XmlWriter<'o>,
    op: Operation,
    root: &'static str,
}

impl<'o> BodyWriter<'o> {
    pub fn writer(&mut self) -> &mut XmlWriter<'o> {
        &mut self.w
    }

    pub fn finish(mut self) {
        self.w.end(M, self.op.response_root());
        close_envelope(&mut self.w, self.root);
    }
}

pub struct MessagesWriter<'o> {
    w: XmlWriter<'o>,
    op: Operation,
    root: &'static str,
}

impl<'o> MessagesWriter<'o> {
    pub fn message<R: ResponseMessage>(&mut self, result: &MessageResult<'_, R>) {
        result.write(&mut self.w, message_element(self.op));
    }

    pub fn written_bytes(&self) -> usize {
        self.w.len()
    }

    pub fn begin_message(&mut self, status: &Status<'_>) -> MessageBodyWriter<'_, 'o> {
        let element = message_element(self.op);
        status.start(&mut self.w, element);
        MessageBodyWriter {
            w: &mut self.w,
            element,
        }
    }

    pub fn empty_message<R: ResponseMessage>(&mut self, status: &Status<'_>) {
        let element = message_element(self.op);
        status.start(&mut self.w, element);
        R::write_required(&mut self.w);
        self.w.end(M, element);
    }

    pub fn finish(self) {
        self.finish_inner(None::<&NoTail>);
    }

    pub fn finish_with_tail<N: XmlWrite>(self, tail: &N) {
        self.finish_inner(Some(tail));
    }

    fn finish_inner<N: XmlWrite>(mut self, tail: Option<&N>) {
        self.w.end(M, "ResponseMessages");
        if let Some(tail) = tail {
            tail.write(&mut self.w);
        }
        self.w.end(M, self.op.response_root());
        close_envelope(&mut self.w, self.root);
    }
}

struct NoTail;

impl XmlWrite for NoTail {
    fn write(&self, _: &mut XmlWriter<'_>) {}
}

pub struct MessageBodyWriter<'m, 'o> {
    w: &'m mut XmlWriter<'o>,
    element: &'static str,
}

impl<'o> MessageBodyWriter<'_, 'o> {
    pub fn writer(&mut self) -> &mut XmlWriter<'o> {
        self.w
    }

    pub fn finish(self) {
        self.w.end(M, self.element);
    }
}

pub fn write_envelope<B: XmlWrite>(
    out: &mut Vec<u8>,
    version: &ServerVersionInfo,
    body: &B,
    decl: XmlDecl,
) {
    EnvelopeWriter::begin(out, version, decl).body(body);
}
