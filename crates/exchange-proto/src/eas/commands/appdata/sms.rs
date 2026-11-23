/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::borrow::Cow;

use super::{Body, Empty, Opaque, eas_struct};
use crate::eas::tokens::tag::{airsyncbase as asb, email, email2};
use crate::eas::types::EasDateTime;

eas_struct!(Sms<'a> {
    to: Cow<'a, str> = email::TO,
    from: Cow<'a, str> = email::FROM,
    date_received: EasDateTime = email::DATE_RECEIVED,
    importance: u8 = email::IMPORTANCE,
    read: bool = email::READ,
    internet_cpid: Cow<'a, str> = email::INTERNET_CPID,
    flag: Empty = email::FLAG,
    body: Body<'a> = asb::BODY,
    conversation_id: Opaque<'a> = email2::CONVERSATION_ID,
    conversation_index: Opaque<'a> = email2::CONVERSATION_INDEX,
});
