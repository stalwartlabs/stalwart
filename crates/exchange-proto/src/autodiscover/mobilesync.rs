/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::pox::write::{begin_document, close, line, newline, open, open_ns};
use crate::xml::{Ns, XmlWriter};
use smallvec::SmallVec;
use std::{borrow::Cow, iter};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MobileSyncResponse<'x> {
    pub culture: &'static str,
    pub display_name: Option<Cow<'x, str>>,
    pub email: Cow<'x, str>,
    pub action: MobileSyncAction<'x>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MobileSyncAction<'x> {
    Redirect(Cow<'x, str>),
    Settings {
        server: MobileServer<'x>,
        more_servers: SmallVec<[MobileServer<'x>; 1]>,
    },
    Error {
        status: u8,
        message: Cow<'x, str>,
        debug_data: Cow<'x, str>,
        error_code: u32,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MobileServer<'x> {
    MobileSync {
        url: Cow<'x, str>,
    },
    CertEnroll {
        url: Cow<'x, str>,
        server_data: Option<Cow<'x, str>>,
    },
}

pub fn write_mobilesync_response(out: &mut Vec<u8>, resp: &MobileSyncResponse<'_>) {
    let mut w = XmlWriter::new(out);
    begin_document(&mut w);
    open_ns(&mut w, "Response", Ns::AdResponseMobile);
    line(&mut w, "Culture", resp.culture);
    open(&mut w, "User");
    if let Some(display_name) = &resp.display_name {
        line(&mut w, "DisplayName", display_name);
    }
    line(&mut w, "EMailAddress", &resp.email);
    close(&mut w, "User");

    open(&mut w, "Action");
    match &resp.action {
        MobileSyncAction::Redirect(address) => line(&mut w, "Redirect", address),
        MobileSyncAction::Settings {
            server,
            more_servers,
        } => {
            open(&mut w, "Settings");
            for server in iter::once(server).chain(more_servers) {
                open(&mut w, "Server");
                match server {
                    MobileServer::MobileSync { url } => {
                        line(&mut w, "Type", "MobileSync");
                        line(&mut w, "Url", url);
                        line(&mut w, "Name", url);
                    }
                    MobileServer::CertEnroll { url, server_data } => {
                        line(&mut w, "Type", "CertEnroll");
                        line(&mut w, "Url", url);
                        w.empty_leaf("", "Name");
                        newline(&mut w);
                        if let Some(server_data) = server_data {
                            line(&mut w, "ServerData", server_data);
                        }
                    }
                }
                close(&mut w, "Server");
            }
            close(&mut w, "Settings");
        }
        MobileSyncAction::Error {
            status,
            message,
            debug_data,
            error_code,
        } => {
            open(&mut w, "Error");
            w.leaf_u64("", "Status", u64::from(*status));
            newline(&mut w);
            line(&mut w, "Message", message);
            line(&mut w, "DebugData", debug_data);
            w.leaf_u64("", "ErrorCode", u64::from(*error_code));
            newline(&mut w);
            close(&mut w, "Error");
        }
    }
    close(&mut w, "Action");
    close(&mut w, "Response");
    close(&mut w, "Autodiscover");
}
