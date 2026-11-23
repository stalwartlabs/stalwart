/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::value::enum_set;
use crate::ews::schema::MailTipType;

enum_set!(pub struct MailTipSet(MailTipType) list "MailTipsRequested");
