/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::common::Guid;
use arrayvec::ArrayString;
use std::{borrow::Cow, num::NonZeroU32};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutlookResponse<'x> {
    pub user: AdUser<'x>,
    pub account: AdAccount<'x>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OutlookRedirect<'x> {
    Addr(Cow<'x, str>),
    Url(Cow<'x, str>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdUser<'x> {
    pub display_name: Cow<'x, str>,
    pub legacy_dn: Cow<'x, str>,
    pub smtp_address: Cow<'x, str>,
    pub deployment_id: Guid,
    pub default_ab_view_contacts: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdAccount<'x> {
    pub microsoft_online: bool,
    pub mailbox: Option<MailboxAccess<'x>>,
    pub ex_http: Option<ExchangeProtocol<'x>>,
    pub web: Option<WebBlocks<'x>>,
    pub imap: Option<MailProtocol<'x>>,
    pub pop3: Option<MailProtocol<'x>>,
    pub smtp: Option<MailProtocol<'x>>,
    pub public_folder_smtp: Option<Cow<'x, str>>,
    pub alternative_mailboxes: Vec<AlternativeMailbox<'x>>,
}

#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MailboxAccess<'x> {
    MapiHttp {
        version: NonZeroU32,
        mail_store: UrlPair<'x>,
        address_book: UrlPair<'x>,
    },
    Rpc(RpcBlocks<'x>),
}

#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RpcBlocks<'x> {
    Exch(ExchangeProtocol<'x>),
    Expr(ExchangeProtocol<'x>),
    Both {
        exch: ExchangeProtocol<'x>,
        expr: ExchangeProtocol<'x>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WebBlocks<'x> {
    Internal(WebBlock<'x>),
    External(WebBlock<'x>),
    Both {
        internal: WebBlock<'x>,
        external: WebBlock<'x>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExchangeProtocol<'x> {
    pub server: Cow<'x, str>,
    pub server_dn: Option<Cow<'x, str>>,
    pub server_version: Option<Cow<'x, str>>,
    pub mdb_dn: Option<Cow<'x, str>>,
    pub ssl: bool,
    pub auth_package: AuthPackage,
    pub as_url: Cow<'x, str>,
    pub ews_url: Cow<'x, str>,
    pub oab_url: Option<Cow<'x, str>>,
    pub oof_url: Option<Cow<'x, str>>,
    pub server_exclusive_connect: bool,
    pub public_folder_server: Option<Cow<'x, str>>,
    pub cert_principal_name: Option<Cow<'x, str>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MailProtocol<'x> {
    pub server: Cow<'x, str>,
    pub port: u16,
    pub login_name: Cow<'x, str>,
    pub ssl: bool,
    pub encryption: Option<Encryption>,
    pub spa: bool,
    pub auth_required: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UrlPair<'x> {
    Internal(Cow<'x, str>),
    External(Cow<'x, str>),
    Both {
        internal: Cow<'x, str>,
        external: Cow<'x, str>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WebBlock<'x> {
    pub owa_url: OwaUrl<'x>,
    pub more_owa_urls: Vec<OwaUrl<'x>>,
    pub as_url: Cow<'x, str>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OwaUrl<'x> {
    pub auth_methods: OwaAuthMethods,
    pub url: Cow<'x, str>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub struct OwaAuthMethods(u8);

pub const OWA_AUTH_TEXT_MAX: usize = 64;

const OWA_AUTH_NAMES: [(OwaAuthMethods, &str); 7] = [
    (OwaAuthMethods::BASIC, "Basic"),
    (OwaAuthMethods::DIGEST, "Digest"),
    (OwaAuthMethods::FBA, "Fba"),
    (OwaAuthMethods::LIVE_ID_FBA, "LiveIdFba"),
    (OwaAuthMethods::NTLM, "Ntlm"),
    (OwaAuthMethods::OAUTH, "OAuth"),
    (OwaAuthMethods::WINDOWS_INTEGRATED, "WindowsIntegrated"),
];

impl OwaAuthMethods {
    pub const WINDOWS_INTEGRATED: Self = OwaAuthMethods(1);
    pub const FBA: Self = OwaAuthMethods(1 << 1);
    pub const NTLM: Self = OwaAuthMethods(1 << 2);
    pub const DIGEST: Self = OwaAuthMethods(1 << 3);
    pub const BASIC: Self = OwaAuthMethods(1 << 4);
    pub const LIVE_ID_FBA: Self = OwaAuthMethods(1 << 5);
    pub const OAUTH: Self = OwaAuthMethods(1 << 6);

    pub const fn empty() -> Self {
        OwaAuthMethods(0)
    }

    pub const fn union(self, other: Self) -> Self {
        OwaAuthMethods(self.0 | other.0)
    }

    pub const fn contains(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }

    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }

    pub const fn bits(self) -> u8 {
        self.0
    }

    pub fn to_text(self) -> ArrayString<OWA_AUTH_TEXT_MAX> {
        let mut text = ArrayString::new();
        for (flag, name) in OWA_AUTH_NAMES {
            if self.contains(flag) {
                let separator = if text.is_empty() { "" } else { ", " };
                if text.try_push_str(separator).is_err() || text.try_push_str(name).is_err() {
                    break;
                }
            }
        }
        text
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthPackage {
    Basic,
    Kerb,
    KerbNtlm,
    Ntlm,
    Certificate,
    Negotiate,
    Anonymous,
}

impl AuthPackage {
    pub const fn as_str(self) -> &'static str {
        match self {
            AuthPackage::Basic => "Basic",
            AuthPackage::Kerb => "Kerb",
            AuthPackage::KerbNtlm => "KerbNtlm",
            AuthPackage::Ntlm => "Ntlm",
            AuthPackage::Certificate => "Certificate",
            AuthPackage::Negotiate => "Negotiate",
            AuthPackage::Anonymous => "Anonymous",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Encryption {
    None,
    Ssl,
    Tls,
    Auto,
}

impl Encryption {
    pub const fn as_str(self) -> &'static str {
        match self {
            Encryption::None => "None",
            Encryption::Ssl => "SSL",
            Encryption::Tls => "TLS",
            Encryption::Auto => "Auto",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AlternativeMailbox<'x> {
    pub kind: AltMailboxKind,
    pub display_name: Cow<'x, str>,
    pub target: AltMailboxTarget<'x>,
    pub owner_smtp_address: Option<Cow<'x, str>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AltMailboxKind {
    Archive,
    Delegate,
    TeamMailbox,
}

impl AltMailboxKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            AltMailboxKind::Archive => "Archive",
            AltMailboxKind::Delegate => "Delegate",
            AltMailboxKind::TeamMailbox => "TeamMailbox",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AltMailboxTarget<'x> {
    Smtp(Cow<'x, str>),
    LegacyDn {
        legacy_dn: Cow<'x, str>,
        server: Cow<'x, str>,
    },
}
