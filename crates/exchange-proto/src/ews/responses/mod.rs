/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

pub mod attachment;
pub mod availability;
pub mod config;
pub mod conversation;
pub mod delegate;
pub mod folder;
pub mod item;
pub mod mailtips;
pub mod notification;
pub mod oof;
pub mod people;
pub mod reminder;
pub mod resolve;
pub mod rules;
pub mod sync;

use crate::{
    ews::{
        operation::{Operation, ResponseShape},
        schema::{ResponseClass, ResponseCode},
        types::{
            path::Path,
            value::{M as MNS, T},
        },
    },
    xml::{XmlWrite, XmlWriter},
};
use smallvec::SmallVec;
use std::borrow::Cow;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Status<'x> {
    pub class: ResponseClass,
    pub code: ResponseCode,
    pub text: Cow<'x, str>,
    pub message_xml: Option<MessageXml<'x>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MessageXml<'x> {
    BackOff { millis: u64 },
    Values(SmallVec<[(&'static str, Cow<'x, str>); 2]>),
    FieldUris(Vec<Path<'x>>),
}

impl<'x> Status<'x> {
    pub const SUCCESS: Status<'static> = Status::success();

    pub const fn success() -> Self {
        Status {
            class: ResponseClass::Success,
            code: ResponseCode::NoError,
            text: Cow::Borrowed(""),
            message_xml: None,
        }
    }

    pub fn error(code: ResponseCode, text: impl Into<Cow<'x, str>>) -> Self {
        Status {
            class: ResponseClass::Error,
            code,
            text: text.into(),
            message_xml: None,
        }
    }

    pub fn warning(code: ResponseCode, text: impl Into<Cow<'x, str>>) -> Self {
        Status {
            class: ResponseClass::Warning,
            code,
            text: text.into(),
            message_xml: None,
        }
    }

    pub fn with_message_xml(mut self, message_xml: MessageXml<'x>) -> Self {
        self.message_xml = Some(message_xml);
        self
    }

    pub fn is_success(&self) -> bool {
        self.class == ResponseClass::Success
    }

    pub fn allows_body(&self) -> bool {
        self.code != ResponseCode::ErrorBatchProcessingStopped
    }

    pub fn write_children(&self, w: &mut XmlWriter<'_>) {
        if self.is_success() {
            w.leaf(MNS, "ResponseCode", self.code.as_str());
        } else {
            w.leaf(MNS, "MessageText", &self.text);
            w.leaf(MNS, "ResponseCode", self.code.as_str());
            w.leaf(MNS, "DescriptiveLinkKey", "0");
            if let Some(message_xml) = &self.message_xml {
                w.start(MNS, "MessageXml");
                message_xml.write_children(w);
                w.end(MNS, "MessageXml");
            }
        }
    }

    pub(crate) fn start(&self, w: &mut XmlWriter<'_>, element: &str) {
        w.start(MNS, element)
            .attr("ResponseClass", self.class.as_str());
        self.write_children(w);
    }
}

impl MessageXml<'_> {
    pub fn write_children(&self, w: &mut XmlWriter<'_>) {
        match self {
            MessageXml::BackOff { millis } => {
                w.start(T, "Value").attr("Name", "BackOffMilliseconds");
                w.text_u64(*millis);
                w.end(T, "Value");
            }
            MessageXml::Values(values) => {
                for (name, value) in values {
                    w.start(T, "Value").attr("Name", name);
                    w.text(value);
                    w.end(T, "Value");
                }
            }
            MessageXml::FieldUris(paths) => {
                for path in paths {
                    path.write(w);
                }
            }
        }
    }
}

const FALLBACK_MESSAGE: &str = "ResponseMessage";
const DELEGATE_MESSAGE: &str = "DelegateUserResponseMessageType";

pub(crate) fn message_element(op: Operation) -> &'static str {
    match op.shape() {
        ResponseShape::D => DELEGATE_MESSAGE,
        _ => op.message_element().unwrap_or(FALLBACK_MESSAGE),
    }
}

pub trait ResponseMessage {
    fn write_body(&self, w: &mut XmlWriter<'_>);

    fn write_required(_w: &mut XmlWriter<'_>) {}
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Paging {
    pub indexed_paging_offset: Option<i32>,
    pub numerator_offset: Option<i32>,
    pub absolute_denominator: Option<i32>,
    pub includes_last_item_in_range: Option<bool>,
    pub total_items_in_view: i32,
}

impl Paging {
    pub fn write_attrs(&self, w: &mut XmlWriter<'_>) {
        if let Some(offset) = self.indexed_paging_offset {
            w.attr_i64("IndexedPagingOffset", offset.into());
        }
        if let Some(offset) = self.numerator_offset {
            w.attr_i64("NumeratorOffset", offset.into());
        }
        if let Some(denominator) = self.absolute_denominator {
            w.attr_i64("AbsoluteDenominator", denominator.into());
        }
        if let Some(last) = self.includes_last_item_in_range {
            w.attr_bool("IncludesLastItemInRange", last);
        }
        w.attr_i64("TotalItemsInView", self.total_items_in_view.into());
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct MessageResult<'x, M> {
    pub status: Status<'x>,
    pub body: Option<M>,
}

impl<M: ResponseMessage> MessageResult<'_, M> {
    pub fn write(&self, w: &mut XmlWriter<'_>, element: &str) {
        self.status.start(w, element);
        match self.body.as_ref().filter(|_| self.status.allows_body()) {
            Some(body) => body.write_body(w),
            None => M::write_required(w),
        }
        w.end(MNS, element);
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct ShapeA<'x, M: ResponseMessage> {
    pub op: Operation,
    pub messages: Vec<MessageResult<'x, M>>,
}

impl<M: ResponseMessage> XmlWrite for ShapeA<'_, M> {
    fn write(&self, w: &mut XmlWriter<'_>) {
        let root = self.op.response_root();
        w.start(MNS, root);
        w.start(MNS, "ResponseMessages");
        let element = message_element(self.op);
        for message in &self.messages {
            message.write(w, element);
        }
        w.end(MNS, "ResponseMessages");
        w.end(MNS, root);
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct ShapeB<'x, M> {
    pub op: Operation,
    pub status: Status<'x>,
    pub body: Option<M>,
}

impl<M: ResponseMessage> XmlWrite for ShapeB<'_, M> {
    fn write(&self, w: &mut XmlWriter<'_>) {
        let root = self.op.response_root();
        self.status.start(w, root);
        match self.body.as_ref().filter(|_| self.status.allows_body()) {
            Some(body) => body.write_body(w),
            None => M::write_required(w),
        }
        w.end(MNS, root);
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct ShapeD<'x, M: ResponseMessage, N> {
    pub op: Operation,
    pub status: Status<'x>,
    pub messages: Vec<MessageResult<'x, M>>,
    pub tail: Option<N>,
}

impl<M: ResponseMessage, N: XmlWrite> XmlWrite for ShapeD<'_, M, N> {
    fn write(&self, w: &mut XmlWriter<'_>) {
        let root = self.op.response_root();
        self.status.start(w, root);
        if !self.messages.is_empty() {
            w.start(MNS, "ResponseMessages");
            let element = message_element(self.op);
            for message in &self.messages {
                message.write(w, element);
            }
            w.end(MNS, "ResponseMessages");
        }
        if let Some(tail) = &self.tail {
            tail.write(w);
        }
        w.end(MNS, root);
    }
}
