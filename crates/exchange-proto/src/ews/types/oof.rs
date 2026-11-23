/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{
    availability::TimeWindow,
    value::{EwsValue, T, ews_struct},
};
use crate::{
    ews::{
        parser::{Parser, Result},
        schema::{ExternalAudience, OofState},
    },
    xml::{Attrs, XmlWriter},
};
use std::borrow::Cow;

#[derive(Debug, Clone, PartialEq, Default)]
pub struct ReplyBody<'a> {
    pub message: Option<Cow<'a, str>>,
    pub lang: Option<Cow<'a, str>>,
}

impl<'a> EwsValue<'a> for ReplyBody<'a> {
    fn parse(p: &mut Parser<'a>, attrs: &Attrs<'a>) -> Result<Self> {
        let lang = p.xml_lang(attrs)?;
        let mut message = None;
        while let Some(child) = p.child()? {
            if child.local == "Message" {
                p.expect_types(&child)?;
                message = Some(p.text()?);
            } else {
                p.skip()?;
            }
        }
        Ok(ReplyBody { message, lang })
    }

    fn write(&self, w: &mut XmlWriter<'_>, local: &str) {
        w.start(T, local);
        if let Some(lang) = &self.lang {
            w.attr("xml:lang", lang);
        }
        w.start(T, "Message");
        if let Some(message) = self
            .message
            .as_deref()
            .filter(|message| !message.is_empty())
        {
            w.text(message);
        }
        w.end(T, "Message");
        w.end(T, local);
    }
}

ews_struct! {
    pub struct UserOofSettings<'x> {
        oof_state: req "OofState" => OofState,
        external_audience: req "ExternalAudience" => ExternalAudience,
        duration: opt "Duration" => TimeWindow,
        internal_reply: opt "InternalReply" => ReplyBody<'x>,
        external_reply: opt "ExternalReply" => ReplyBody<'x>,
        decline_meeting_reply: opt "DeclineMeetingReply" => ReplyBody<'x>,
        decline_events_for_scheduled_oof: opt "DeclineEventsForScheduledOOF" => bool,
        decline_all_events_for_scheduled_oof: opt "DeclineAllEventsForScheduledOOF" => bool,
        create_oof_event: opt "CreateOOFEvent" => bool,
        oof_event_subject: opt "OOFEventSubject" => Cow<'x, str>,
        auto_decline_future_requests_when_oof: opt "AutoDeclineFutureRequestsWhenOOF" => bool,
        oof_event_id: opt "OOFEventID" => Cow<'x, str>,
    }
}
