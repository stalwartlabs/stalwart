/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    responses::{XmlCdataEscape, XmlEscape},
    schema::{
        Namespaces,
        response::{ScheduleResponse, ScheduleResponseItem},
    },
};
use std::fmt::Display;

const NAMESPACE: Namespaces = Namespaces {
    cal: true,
    card: false,
    cs: false,
};

impl Display for ScheduleResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "<?xml version=\"1.0\" encoding=\"UTF-8\"?>")?;
        write!(
            f,
            "<A:schedule-response {NAMESPACE}>{}</A:schedule-response>",
            self.items
        )
    }
}

impl Display for ScheduleResponseItem {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "<A:response>")?;
        write!(f, "<A:recipient>{}</A:recipient>", self.recipient)?;

        write!(f, "<A:request-status>")?;
        self.request_status.write_escaped_to(f)?;
        write!(f, "</A:request-status>")?;

        if let Some(calendar_data) = &self.calendar_data {
            write!(f, "<A:calendar-data>")?;
            calendar_data.write_cdata_escaped_to(f)?;
            write!(f, "</A:calendar-data>")?;
        }
        write!(f, "</A:response>")
    }
}
