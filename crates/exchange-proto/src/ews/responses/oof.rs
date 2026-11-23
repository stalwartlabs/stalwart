/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::Status;
use crate::{
    ews::{
        schema::{ExternalAudience, OofState},
        types::{
            availability::TimeWindow,
            oof::ReplyBody,
            value::{EwsValue, M, T},
        },
    },
    xml::{XmlWrite, XmlWriter},
};

const STATUS_ELEMENT: &str = "ResponseMessage";

#[derive(Debug, Clone, PartialEq)]
pub struct OofSettings<'x> {
    pub oof_state: OofState,
    pub external_audience: ExternalAudience,
    pub duration: TimeWindow,
    pub internal_reply: ReplyBody<'x>,
    pub external_reply: ReplyBody<'x>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct GetUserOofSettingsResponse<'x> {
    pub status: Status<'x>,
    pub settings: Option<OofSettings<'x>>,
    pub allow_external_oof: ExternalAudience,
}

impl XmlWrite for GetUserOofSettingsResponse<'_> {
    fn write(&self, w: &mut XmlWriter<'_>) {
        w.start(M, "GetUserOofSettingsResponse");
        self.status.start(w, STATUS_ELEMENT);
        w.end(M, STATUS_ELEMENT);
        if let Some(settings) = self.settings.as_ref().filter(|_| self.status.allows_body()) {
            w.start(T, "OofSettings");
            settings.oof_state.write(w, "OofState");
            settings.external_audience.write(w, "ExternalAudience");
            settings.duration.write(w, "Duration");
            settings.internal_reply.write(w, "InternalReply");
            settings.external_reply.write(w, "ExternalReply");
            w.end(T, "OofSettings");
            w.leaf(M, "AllowExternalOof", self.allow_external_oof.as_str());
        }
        w.end(M, "GetUserOofSettingsResponse");
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct SetUserOofSettingsResponse<'x> {
    pub status: Status<'x>,
}

impl XmlWrite for SetUserOofSettingsResponse<'_> {
    fn write(&self, w: &mut XmlWriter<'_>) {
        w.start(M, "SetUserOofSettingsResponse");
        self.status.start(w, STATUS_ELEMENT);
        w.end(M, STATUS_ELEMENT);
        w.end(M, "SetUserOofSettingsResponse");
    }
}
