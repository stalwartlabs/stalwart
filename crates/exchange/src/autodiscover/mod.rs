/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

pub(crate) mod json;
pub mod pox;
pub mod soap;

use crate::identity;
use common::{Server, auth::AccessToken};
use types::type_state::DataType;
use utils::map::bitmap::Bitmap;

const EWS_PATH: &str = "/EWS/Exchange.asmx";
const EAS_PATH: &str = "/Microsoft-Server-ActiveSync";
const EWS_DATA_TYPES: [DataType; 3] = [
    DataType::Email,
    DataType::CalendarEvent,
    DataType::ContactCard,
];

pub(crate) struct Endpoints<'x> {
    pub base: &'x str,
    pub host: &'x str,
}

impl<'x> Endpoints<'x> {
    pub fn new(server: &'x Server) -> Self {
        Self::from_base(&server.core.network.http.url_https)
    }

    pub fn from_base(base: &'x str) -> Self {
        let base = base.trim_end_matches('/');
        let host = base
            .split_once("://")
            .map_or(base, |(_, rest)| rest)
            .split('/')
            .next()
            .unwrap_or_default();
        Endpoints { base, host }
    }

    pub fn url(&self, path: &str) -> String {
        let mut url = String::with_capacity(self.base.len() + path.len());
        url.push_str(self.base);
        url.push_str(path);
        url
    }

    pub fn ews(&self) -> String {
        self.url(EWS_PATH)
    }

    pub fn eas(&self) -> String {
        self.url(EAS_PATH)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum MailboxAddress<'x> {
    Smtp(&'x str),
    LegacyDn(&'x str),
    Own,
}

impl<'x> MailboxAddress<'x> {
    pub fn parse(address: &'x str) -> Self {
        let address = address.trim();
        if address.starts_with('/') {
            MailboxAddress::LegacyDn(address)
        } else {
            MailboxAddress::Smtp(address)
        }
    }
}

pub(crate) struct Mailbox {
    pub account_id: u32,
    pub primary: String,
    pub display_name: Box<str>,
    pub smtp: String,
}

pub(crate) fn has_data_access(access_token: &AccessToken) -> bool {
    let mut types = Bitmap::all();
    access_token.restrict_data_types(&mut types);
    types.contains_any(EWS_DATA_TYPES.into_iter())
}

pub(crate) async fn resolve_mailbox(
    server: &Server,
    access_token: &AccessToken,
    address: MailboxAddress<'_>,
) -> trc::Result<Option<Mailbox>> {
    let account_id = match address {
        MailboxAddress::Smtp(email) => server.account_id_from_email(email, false).await?,
        MailboxAddress::LegacyDn(dn) => identity::principal_from_dn(dn.as_bytes()),
        MailboxAddress::Own => Some(access_token.account_id()),
    };
    let Some(account_id) = account_id.filter(|&account_id| {
        access_token.is_member(account_id) || access_token.all_ids().any(|id| id == account_id)
    }) else {
        return Ok(None);
    };
    let info = server.account_info(account_id).await?;
    let primary = info
        .addresses
        .into_iter()
        .next()
        .unwrap_or_else(|| info.account.name.to_string());
    let smtp = match address {
        MailboxAddress::Smtp(email) => email.to_ascii_lowercase(),
        MailboxAddress::LegacyDn(_) | MailboxAddress::Own => primary.clone(),
    };
    Ok(Some(Mailbox {
        account_id,
        primary,
        display_name: info
            .account
            .description
            .clone()
            .unwrap_or_else(|| info.account.name.clone()),
        smtp,
    }))
}

#[cfg(all(test, stalwart_tests))]
#[rustfmt::skip]
#[path = "../../../../../stalwart-tests/unit/exchange/src/autodiscover/tests.rs"]
mod tests;
