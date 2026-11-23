/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::borrow::Cow;

use super::{Body, Compact, List, eas_struct};
use crate::eas::tokens::tag::{airsyncbase as asb, notes};

pub type Categories<'a> = List<Cow<'a, str>, { notes::CATEGORY.raw() }>;

eas_struct!(Note<'a> {
    subject: Cow<'a, str> = notes::SUBJECT,
    body: Body<'a> = asb::BODY,
    message_class: Cow<'a, str> = notes::MESSAGE_CLASS,
    last_modified_date: Compact = notes::LAST_MODIFIED_DATE,
    categories: Categories<'a> = notes::CATEGORIES,
});
