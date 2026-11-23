/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

pub mod parse;
pub mod write;

use super::{
    pox::{AltMailboxKind, AltMailboxTarget, Encryption, OwaAuthMethods},
    settings::{SettingKind, UserSettingName},
};
use crate::{ews::version::ExchangeVersion, xml::XmlError, xml::XmlErrorKind};
use smallvec::SmallVec;
use std::borrow::Cow;

pub use parse::parse_soap_request;
pub use write::{
    write_federation_not_federated, write_get_domain_settings, write_get_user_settings,
    write_soap_error, write_soap_fault,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SoapAdEnvelope<'a> {
    pub requested_version: Option<Cow<'a, str>>,
    pub request_version: Option<ExchangeVersion>,
    pub request: SoapAdRequest<'a>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SoapOperation {
    GetUserSettings,
    GetDomainSettings,
    GetFederationInformation,
    GetOrganizationRelationshipSettings,
}

impl SoapOperation {
    pub fn from_request_root(local: &[u8]) -> Option<Self> {
        hashify::map!(
            local,
            SoapOperation,
            "GetUserSettingsRequestMessage" => SoapOperation::GetUserSettings,
            "GetDomainSettingsRequestMessage" => SoapOperation::GetDomainSettings,
            "GetFederationInformationRequestMessage" => SoapOperation::GetFederationInformation,
            "GetOrganizationRelationshipSettingsRequestMessage" => SoapOperation::GetOrganizationRelationshipSettings,
        )
        .copied()
    }

    pub const fn name(self) -> &'static str {
        match self {
            SoapOperation::GetUserSettings => "GetUserSettings",
            SoapOperation::GetDomainSettings => "GetDomainSettings",
            SoapOperation::GetFederationInformation => "GetFederationInformation",
            SoapOperation::GetOrganizationRelationshipSettings => {
                "GetOrganizationRelationshipSettings"
            }
        }
    }

    pub const fn response_root(self) -> &'static str {
        match self {
            SoapOperation::GetUserSettings => "GetUserSettingsResponseMessage",
            SoapOperation::GetDomainSettings => "GetDomainSettingsResponseMessage",
            SoapOperation::GetFederationInformation => "GetFederationInformationResponseMessage",
            SoapOperation::GetOrganizationRelationshipSettings => {
                "GetOrganizationRelationshipSettingsResponseMessage"
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SoapAdRequest<'a> {
    GetUserSettings {
        users: SmallVec<[Cow<'a, str>; 1]>,
        settings: Vec<RequestedSetting<'a>>,
    },
    GetDomainSettings {
        domains: SmallVec<[Cow<'a, str>; 1]>,
        settings: Vec<RequestedSetting<'a>>,
    },
    GetFederationInformation {
        domain: Cow<'a, str>,
    },
    GetOrganizationRelationshipSettings,
}

impl SoapAdRequest<'_> {
    pub const fn operation(&self) -> SoapOperation {
        match self {
            SoapAdRequest::GetUserSettings { .. } => SoapOperation::GetUserSettings,
            SoapAdRequest::GetDomainSettings { .. } => SoapOperation::GetDomainSettings,
            SoapAdRequest::GetFederationInformation { .. } => {
                SoapOperation::GetFederationInformation
            }
            SoapAdRequest::GetOrganizationRelationshipSettings => {
                SoapOperation::GetOrganizationRelationshipSettings
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RequestedSetting<'a> {
    Known(UserSettingName),
    Unknown(Cow<'a, str>),
}

impl RequestedSetting<'_> {
    pub fn as_str(&self) -> &str {
        match self {
            RequestedSetting::Known(name) => name.as_str(),
            RequestedSetting::Unknown(name) => name,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SoapInvalid {
    MissingRequest,
    MissingUsers,
    MissingMailbox,
    MissingDomain,
    MissingSettings,
    TooManyItems,
    TooManySettings,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SoapParseErrorKind {
    Xml(XmlErrorKind),
    NotEnvelope,
    MissingBody,
    UnknownOperation,
    Invalid(SoapOperation, SoapInvalid),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SoapParseError {
    pub kind: SoapParseErrorKind,
    pub offset: u32,
}

const _: () = assert!(std::mem::size_of::<SoapParseError>() <= 8);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SoapParseOutcome {
    Fault,
    Error {
        op: SoapOperation,
        code: SoapErrorCode,
    },
}

impl SoapParseError {
    pub const fn outcome(&self) -> SoapParseOutcome {
        match self.kind {
            SoapParseErrorKind::Invalid(op, _) => SoapParseOutcome::Error {
                op,
                code: SoapErrorCode::InvalidRequest,
            },
            _ => SoapParseOutcome::Fault,
        }
    }

    const fn new(kind: SoapParseErrorKind, offset: u32) -> Self {
        SoapParseError { kind, offset }
    }
}

impl From<XmlError> for SoapParseError {
    fn from(err: XmlError) -> Self {
        SoapParseError::new(SoapParseErrorKind::Xml(err.kind), err.offset)
    }
}

impl std::fmt::Display for SoapParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?} at byte {}", self.kind, self.offset)
    }
}

impl std::error::Error for SoapParseError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SoapErrorCode {
    NoError,
    RedirectAddress,
    RedirectUrl,
    InvalidUser,
    InvalidRequest,
    InvalidSetting,
    SettingIsNotAvailable,
    ServerBusy,
    InvalidDomain,
    NotFederated,
    InternalServerError,
}

impl SoapErrorCode {
    pub const fn as_str(self) -> &'static str {
        match self {
            SoapErrorCode::NoError => "NoError",
            SoapErrorCode::RedirectAddress => "RedirectAddress",
            SoapErrorCode::RedirectUrl => "RedirectUrl",
            SoapErrorCode::InvalidUser => "InvalidUser",
            SoapErrorCode::InvalidRequest => "InvalidRequest",
            SoapErrorCode::InvalidSetting => "InvalidSetting",
            SoapErrorCode::SettingIsNotAvailable => "SettingIsNotAvailable",
            SoapErrorCode::ServerBusy => "ServerBusy",
            SoapErrorCode::InvalidDomain => "InvalidDomain",
            SoapErrorCode::NotFederated => "NotFederated",
            SoapErrorCode::InternalServerError => "InternalServerError",
        }
    }

    pub const fn default_message(self) -> &'static str {
        match self {
            SoapErrorCode::NoError => "No error.",
            SoapErrorCode::RedirectAddress => "Redirection address.",
            SoapErrorCode::RedirectUrl => "Redirection URL.",
            SoapErrorCode::InvalidUser => "Invalid user.",
            SoapErrorCode::InvalidRequest => "Invalid request.",
            SoapErrorCode::InvalidSetting => "Invalid setting.",
            SoapErrorCode::SettingIsNotAvailable => "Setting is not available.",
            SoapErrorCode::ServerBusy => "Server busy.",
            SoapErrorCode::InvalidDomain => "Invalid domain.",
            SoapErrorCode::NotFederated => "The organization is not federated.",
            SoapErrorCode::InternalServerError => "Internal server error.",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProtocolConnection<'x> {
    pub hostname: Cow<'x, str>,
    pub port: u16,
    pub encryption: Option<Encryption>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WebClientUrl<'x> {
    pub auth_methods: OwaAuthMethods,
    pub url: Cow<'x, str>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AlternateMailbox<'x> {
    pub kind: AltMailboxKind,
    pub display_name: Cow<'x, str>,
    pub target: AltMailboxTarget<'x>,
    pub owner_smtp_address: Option<Cow<'x, str>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DomainSettingName {
    ExternalEwsUrl,
    ExternalEwsVersion,
}

impl DomainSettingName {
    pub const fn as_str(self) -> &'static str {
        match self {
            DomainSettingName::ExternalEwsUrl => "ExternalEwsUrl",
            DomainSettingName::ExternalEwsVersion => "ExternalEwsVersion",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DomainResponse<'x> {
    pub error: SoapErrorCode,
    pub message: Cow<'x, str>,
    pub settings: Vec<(DomainSettingName, Cow<'x, str>)>,
    pub setting_errors: Vec<(RequestedSetting<'x>, SoapErrorCode)>,
    pub redirect_target: Option<Cow<'x, str>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UserSettingValue<'x> {
    String(Cow<'x, str>),
    ProtocolConnections(Vec<ProtocolConnection<'x>>),
    WebClientUrls(Vec<WebClientUrl<'x>>),
    AlternateMailboxes(Vec<AlternateMailbox<'x>>),
}

impl UserSettingValue<'_> {
    pub const fn kind(&self) -> SettingKind {
        match self {
            UserSettingValue::String(_) => SettingKind::String,
            UserSettingValue::ProtocolConnections(_) => SettingKind::ProtocolConnections,
            UserSettingValue::WebClientUrls(_) => SettingKind::WebClientUrls,
            UserSettingValue::AlternateMailboxes(_) => SettingKind::AlternateMailboxes,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UserResponse<'x> {
    pub error: SoapErrorCode,
    pub message: Cow<'x, str>,
    pub redirect_target: Option<Cow<'x, str>>,
    pub settings: Vec<(UserSettingName, UserSettingValue<'x>)>,
    pub setting_errors: Vec<(RequestedSetting<'x>, SoapErrorCode)>,
}
