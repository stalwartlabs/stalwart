/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{
    ids::{BaseFolderId, Watermark},
    value::{EwsValue, enum_set, parse_bounded},
};
use crate::ews::{
    parser::{Child, ParseErrorKind, Parser, Result},
    schema::NotificationEventType,
};
use std::borrow::Cow;

const MAX_SUBSCRIPTION_MINUTES: u16 = 1440;

enum_set!(pub struct EventTypes(NotificationEventType));

#[derive(Debug, Clone, PartialEq)]
pub enum SubscriptionFolders<'a> {
    All,
    Some(Vec<BaseFolderId<'a>>),
}

#[derive(Debug, Clone, PartialEq)]
pub enum SubscriptionRequest<'a> {
    Pull {
        folders: SubscriptionFolders<'a>,
        events: EventTypes,
        watermark: Option<Watermark<'a>>,
        timeout: u16,
    },
    Push {
        folders: SubscriptionFolders<'a>,
        events: EventTypes,
        watermark: Option<Watermark<'a>>,
        status_frequency: u16,
        url: Cow<'a, str>,
        caller_data: Option<Cow<'a, str>>,
    },
    Streaming {
        folders: SubscriptionFolders<'a>,
        events: EventTypes,
    },
}

#[derive(Clone, Copy)]
enum SubscriptionKind {
    Pull,
    Push,
    Streaming,
}

#[derive(Default)]
struct Scratch<'a> {
    folders: Option<Vec<BaseFolderId<'a>>>,
    events: Option<EventTypes>,
    watermark: Option<Watermark<'a>>,
    timeout: Option<u16>,
    status_frequency: Option<u16>,
    url: Option<Cow<'a, str>>,
    caller_data: Option<Cow<'a, str>>,
}

impl<'a> SubscriptionRequest<'a> {
    pub fn parse_child(p: &mut Parser<'a>, child: &Child<'a>) -> Result<Option<Self>> {
        let Some(kind) = hashify::map!(child.local.as_bytes(), SubscriptionKind,
            "PullSubscriptionRequest" => SubscriptionKind::Pull,
            "PushSubscriptionRequest" => SubscriptionKind::Push,
            "StreamingSubscriptionRequest" => SubscriptionKind::Streaming,
        )
        .copied() else {
            return Ok(None);
        };
        p.expect_messages(child)?;
        let all_folders: Option<bool> = p.attr_value(&child.attrs, "SubscribeToAllFolders")?;
        let mut scratch = Scratch::default();
        while let Some(child) = p.child()? {
            hashify::fnc_map!(child.local.as_bytes(),
                "FolderIds" => {
                    p.expect_types(&child)?;
                    scratch.folders = Some(BaseFolderId::parse_list(p)?);
                },
                "EventTypes" => {
                    p.expect_types(&child)?;
                    scratch.events = Some(parse_event_types(p)?);
                },
                "Watermark" => {
                    scratch.watermark = Some(Watermark::parse(p, &child.attrs)?);
                },
                "Timeout" => {
                    p.expect_types(&child)?;
                    scratch.timeout = Some(parse_bounded(p, "Timeout", 1, MAX_SUBSCRIPTION_MINUTES)?);
                },
                "StatusFrequency" => {
                    p.expect_types(&child)?;
                    scratch.status_frequency =
                        Some(parse_bounded(p, "StatusFrequency", 1, MAX_SUBSCRIPTION_MINUTES)?);
                },
                "URL" => {
                    p.expect_types(&child)?;
                    scratch.url = Some(p.text()?);
                },
                "CallerData" => {
                    p.expect_types(&child)?;
                    scratch.caller_data = Some(p.text()?);
                },
                _ => {
                    p.skip()?;
                }
            );
        }
        let folders = match (all_folders.unwrap_or(false), scratch.folders) {
            (true, None) => SubscriptionFolders::All,
            (true, Some(folders)) if folders.is_empty() => SubscriptionFolders::All,
            (false, Some(folders)) if !folders.is_empty() => SubscriptionFolders::Some(folders),
            _ => return Err(p.error(ParseErrorKind::InvalidSubscription)),
        };
        let events = scratch
            .events
            .filter(|events| !events.is_empty())
            .ok_or_else(|| p.error(ParseErrorKind::MissingElement("EventTypes")))?;
        let missing = |p: &Parser<'a>, name| p.error(ParseErrorKind::MissingElement(name));
        Ok(Some(match kind {
            SubscriptionKind::Pull => SubscriptionRequest::Pull {
                folders,
                events,
                watermark: scratch.watermark,
                timeout: scratch.timeout.ok_or_else(|| missing(p, "Timeout"))?,
            },
            SubscriptionKind::Push => SubscriptionRequest::Push {
                folders,
                events,
                watermark: scratch.watermark,
                status_frequency: scratch
                    .status_frequency
                    .ok_or_else(|| missing(p, "StatusFrequency"))?,
                url: scratch.url.ok_or_else(|| missing(p, "URL"))?,
                caller_data: scratch.caller_data,
            },
            SubscriptionKind::Streaming => SubscriptionRequest::Streaming { folders, events },
        }))
    }
}

fn parse_event_types(p: &mut Parser<'_>) -> Result<EventTypes> {
    let mut events = EventTypes::default();
    while let Some(child) = p.child()? {
        if child.local == "EventType" {
            p.expect_types(&child)?;
            events.insert(p.text_enum("EventType", NotificationEventType::parse)?);
        } else {
            p.skip()?;
        }
    }
    Ok(events)
}
