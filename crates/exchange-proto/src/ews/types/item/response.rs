/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{ItemFields, MessageFields};
use crate::{
    ews::{
        parser::{Parser, Result},
        types::{
            common::Body,
            ids::ItemId,
            value::{DateTime, EwsValue, T, ews_fields},
        },
    },
    xml::{Attrs, XmlWriter},
};
use std::borrow::Cow;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ResponseObjectKind {
    Accept,
    TentativelyAccept,
    Decline,
    ReplyTo,
    ReplyAll,
    Forward,
    CancelCalendarItem,
    Remove,
    SuppressReadReceipt,
    PostReply,
    AcceptSharingInvitation,
    AddItemToMyCalendar,
    ProposeNewTime,
}

impl ResponseObjectKind {
    pub const ALL: &'static [ResponseObjectKind] = &[
        ResponseObjectKind::Accept,
        ResponseObjectKind::TentativelyAccept,
        ResponseObjectKind::Decline,
        ResponseObjectKind::ReplyTo,
        ResponseObjectKind::Forward,
        ResponseObjectKind::ReplyAll,
        ResponseObjectKind::CancelCalendarItem,
        ResponseObjectKind::Remove,
        ResponseObjectKind::SuppressReadReceipt,
        ResponseObjectKind::PostReply,
        ResponseObjectKind::AcceptSharingInvitation,
        ResponseObjectKind::AddItemToMyCalendar,
        ResponseObjectKind::ProposeNewTime,
    ];

    pub const fn element(self) -> &'static str {
        match self {
            ResponseObjectKind::Accept => "AcceptItem",
            ResponseObjectKind::TentativelyAccept => "TentativelyAcceptItem",
            ResponseObjectKind::Decline => "DeclineItem",
            ResponseObjectKind::ReplyTo => "ReplyToItem",
            ResponseObjectKind::ReplyAll => "ReplyAllToItem",
            ResponseObjectKind::Forward => "ForwardItem",
            ResponseObjectKind::CancelCalendarItem => "CancelCalendarItem",
            ResponseObjectKind::Remove => "RemoveItem",
            ResponseObjectKind::SuppressReadReceipt => "SuppressReadReceipt",
            ResponseObjectKind::PostReply => "PostReplyItem",
            ResponseObjectKind::AcceptSharingInvitation => "AcceptSharingInvitation",
            ResponseObjectKind::AddItemToMyCalendar => "AddItemToMyCalendar",
            ResponseObjectKind::ProposeNewTime => "ProposeNewTime",
        }
    }

    const fn bit(self) -> u16 {
        1 << self as u16
    }
}

const _: () = assert!(ResponseObjectKind::ALL.len() <= u16::BITS as usize);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ResponseObjectSet(u16);

impl ResponseObjectSet {
    pub const EMPTY: Self = ResponseObjectSet(0);

    pub fn insert(&mut self, kind: ResponseObjectKind) {
        self.0 |= kind.bit();
    }

    pub const fn contains(self, kind: ResponseObjectKind) -> bool {
        self.0 & kind.bit() != 0
    }

    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }

    pub fn iter(self) -> impl Iterator<Item = ResponseObjectKind> {
        ResponseObjectKind::ALL
            .iter()
            .copied()
            .filter(move |kind| self.contains(*kind))
    }
}

impl FromIterator<ResponseObjectKind> for ResponseObjectSet {
    fn from_iter<I: IntoIterator<Item = ResponseObjectKind>>(iter: I) -> Self {
        let mut set = ResponseObjectSet::EMPTY;
        for kind in iter {
            set.insert(kind);
        }
        set
    }
}

impl<'x> EwsValue<'x> for ResponseObjectSet {
    fn parse(p: &mut Parser<'x>, _: &Attrs<'x>) -> Result<Self> {
        p.skip()?;
        Ok(ResponseObjectSet::EMPTY)
    }

    fn merge(_: &mut Option<Self>, p: &mut Parser<'x>, _: &Attrs<'x>) -> Result<()> {
        p.skip()
    }

    fn write(&self, w: &mut XmlWriter<'_>, local: &str) {
        if !self.is_empty() {
            w.start(T, local);
            for kind in self.iter() {
                w.empty_leaf(T, kind.element());
            }
            w.end(T, local);
        }
    }
}

ews_fields! {
    pub struct ResponseObjectFields<'x> {
        reference_item_id: "ReferenceItemId" => ItemId<'x>,
        new_body_content: "NewBodyContent" => Body<'x>,
        is_specific_message_reply: "IsSpecificMessageReply" => bool,
        proposed_start: "ProposedStart" => DateTime,
        proposed_end: "ProposedEnd" => DateTime,
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct ResponseObject<'x> {
    pub object_name: Option<Cow<'x, str>>,
    pub item: ItemFields<'x>,
    pub message: MessageFields<'x>,
    pub extra: ResponseObjectFields<'x>,
}
