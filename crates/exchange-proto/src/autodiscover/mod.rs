/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

pub mod headers;
pub mod mobilesync;
pub mod pox;
pub mod settings;
pub mod soap;
pub mod v2;

use crate::xml::XmlLimits;

pub use headers::{ClientCanHandle, MapiHttpCapability, user_agent_is_mapi_http_outlook};
pub use mobilesync::{
    MobileServer, MobileSyncAction, MobileSyncResponse, write_mobilesync_response,
};
pub use pox::{
    AdAccount, AdUser, AltMailboxKind, AltMailboxTarget, AlternativeMailbox, AuthPackage,
    Encryption, ExchangeProtocol, MailProtocol, MailboxAccess, OutlookRedirect, OutlookResponse,
    OwaAuthMethods, OwaUrl, PoxErrorCode, PoxParseError, PoxParseErrorKind, PoxRequest, RpcBlocks,
    UrlPair, WebBlock, WebBlocks, parse_pox_request, write_outlook_redirect,
    write_outlook_response, write_pox_error,
};
pub use settings::{SettingKind, UserSettingName};
pub use soap::{
    AlternateMailbox, DomainResponse, DomainSettingName, ProtocolConnection, RequestedSetting,
    SoapAdEnvelope, SoapAdRequest, SoapErrorCode, SoapOperation, SoapParseError,
    SoapParseErrorKind, SoapParseOutcome, UserResponse, UserSettingValue, WebClientUrl,
    parse_soap_request, write_federation_not_federated, write_get_domain_settings,
    write_get_user_settings, write_soap_error, write_soap_fault,
};
pub use v2::{
    V2ErrorCode, V2Protocol, V2Request, parse_v2_request, write_v2_error, write_v2_success,
};

pub const XML_CONTENT_TYPE: &str = "text/xml; charset=utf-8";
pub const JSON_CONTENT_TYPE: &str = "application/json; charset=utf-8";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AdLimits {
    pub xml: XmlLimits,
    pub max_pox_body: u32,
    pub max_users: u16,
    pub max_settings: u16,
}

impl AdLimits {
    pub const DEFAULT: Self = AdLimits {
        xml: XmlLimits::DEFAULT,
        max_pox_body: 8192,
        max_users: 100,
        max_settings: 128,
    };
}

impl Default for AdLimits {
    fn default() -> Self {
        Self::DEFAULT
    }
}

#[cfg(all(test, stalwart_tests))]
#[rustfmt::skip]
#[path = "../../../../../stalwart-tests/unit/exchange-proto/src/autodiscover/tests/mod.rs"]
mod tests;
