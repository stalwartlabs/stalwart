/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{
    Endpoints, Mailbox, MailboxAddress, has_data_access, pox::xml_response, resolve_mailbox,
};
use crate::{ews::server_version, identity, oab::advertised_url};
use common::{Server, auth::AccessToken};
use exchange_proto::{
    autodiscover::{
        AdLimits, DomainResponse, DomainSettingName, Encryption, ProtocolConnection,
        RequestedSetting, SoapAdRequest, SoapErrorCode, SoapParseOutcome, UserResponse,
        UserSettingName, UserSettingValue, parse_soap_request, write_federation_not_federated,
        write_get_domain_settings, write_get_user_settings, write_soap_error, write_soap_fault,
    },
    common::{Braces, HexCase},
    ews::{ExchangeVersion, ServerVersionInfo},
};
use http_proto::{HttpRequest, HttpResponse, HttpSessionData, request::fetch_body};
use hyper::StatusCode;
use registry::schema::enums::ServiceProtocol;
use std::borrow::Cow;

pub trait SoapAutodiscover: Sync + Send {
    fn handle_soap_autodiscover(
        &self,
        request: HttpRequest,
        access_token: Option<AccessToken>,
        session: &HttpSessionData,
    ) -> impl Future<Output = trc::Result<HttpResponse>> + Send;
}

impl SoapAutodiscover for Server {
    async fn handle_soap_autodiscover(
        &self,
        mut request: HttpRequest,
        access_token: Option<AccessToken>,
        session: &HttpSessionData,
    ) -> trc::Result<HttpResponse> {
        let limits = AdLimits::DEFAULT;
        let max_body = if access_token.is_some() {
            self.core.exchange.max_request_size
        } else {
            usize::try_from(limits.max_pox_body).unwrap_or(usize::MAX)
        };
        let Some(body) = fetch_body(&mut request, max_body, session.session_id).await else {
            return Err(trc::LimitEvent::SizeRequest.into_err());
        };
        let version = server_version(self);
        let mut out = Vec::with_capacity(2048);
        let envelope = match parse_soap_request(&body, &limits) {
            Ok(envelope) => envelope,
            Err(err) => {
                return Ok(match err.outcome() {
                    SoapParseOutcome::Fault => {
                        write_soap_fault(&mut out, &err);
                        xml_response(out).with_status_code(StatusCode::INTERNAL_SERVER_ERROR)
                    }
                    SoapParseOutcome::Error { op, code } => {
                        write_soap_error(&mut out, &version, op, code, code.default_message());
                        xml_response(out)
                    }
                });
            }
        };

        let (request, access_token) = match (envelope.request, access_token) {
            (SoapAdRequest::GetFederationInformation { .. }, _) => {
                write_federation_not_federated(&mut out, &version);
                return Ok(xml_response(out));
            }
            (request, Some(access_token)) => (request, access_token),
            (_, None) => {
                return Err(trc::AuthEvent::Failed
                    .into_err()
                    .details("Autodiscover requires authentication."));
            }
        };

        let data_access = has_data_access(&access_token);
        match request {
            SoapAdRequest::GetUserSettings { users, settings } => {
                let mut mailboxes = Vec::with_capacity(users.len());
                let mut slots: Vec<usize> = Vec::with_capacity(users.len());
                for user in &users {
                    let user = user.trim();
                    let earlier = users
                        .iter()
                        .zip(&slots)
                        .find(|(seen, _)| seen.trim().eq_ignore_ascii_case(user))
                        .map(|(_, slot)| *slot);
                    let slot = match earlier {
                        Some(slot) => slot,
                        None => {
                            mailboxes.push(
                                resolve_mailbox(self, &access_token, MailboxAddress::parse(user))
                                    .await?,
                            );
                            mailboxes.len() - 1
                        }
                    };
                    slots.push(slot);
                }
                let oab_url = if data_access
                    && mailboxes.iter().any(Option::is_some)
                    && settings.iter().any(|setting| {
                        matches!(
                            setting,
                            RequestedSetting::Known(
                                UserSettingName::InternalOABUrl | UserSettingName::ExternalOABUrl
                            )
                        )
                    }) {
                    advertised_url(self, &access_token).await
                } else {
                    None
                };
                let responses = slots
                    .iter()
                    .map(|slot| match mailboxes.get(*slot).and_then(Option::as_ref) {
                        Some(mailbox) => user_response(
                            self,
                            &version,
                            mailbox,
                            data_access,
                            oab_url.as_deref(),
                            &settings,
                        ),
                        None => error_user_response(SoapErrorCode::InvalidUser),
                    })
                    .collect::<Vec<_>>();
                write_get_user_settings(&mut out, &version, &responses);
            }
            SoapAdRequest::GetDomainSettings { domains, settings } => {
                let mut responses = Vec::with_capacity(domains.len());
                for domain in &domains {
                    let local = self.domain(domain.trim()).await?.is_some();
                    responses.push(domain_response(
                        self,
                        &version,
                        local,
                        data_access,
                        &settings,
                    ));
                }
                write_get_domain_settings(&mut out, &version, &responses);
            }
            request => {
                let op = request.operation();
                let code = SoapErrorCode::InvalidRequest;
                write_soap_error(&mut out, &version, op, code, code.default_message());
            }
        }
        Ok(xml_response(out))
    }
}

fn error_user_response(code: SoapErrorCode) -> UserResponse<'static> {
    UserResponse {
        error: code,
        message: Cow::Borrowed(code.default_message()),
        redirect_target: None,
        settings: Vec::new(),
        setting_errors: Vec::new(),
    }
}

fn user_response<'x>(
    server: &'x Server,
    version: &ServerVersionInfo,
    mailbox: &'x Mailbox,
    data_access: bool,
    oab_url: Option<&'x str>,
    requested: &[RequestedSetting<'x>],
) -> UserResponse<'x> {
    let endpoints = Endpoints::new(server);
    let mut settings = Vec::with_capacity(requested.len());
    let mut setting_errors = Vec::new();
    for setting in requested {
        let value = match setting {
            RequestedSetting::Known(name) => user_setting(
                server,
                version,
                &endpoints,
                mailbox,
                data_access,
                oab_url,
                *name,
            ),
            RequestedSetting::Unknown(_) => None,
        };
        match (setting, value) {
            (RequestedSetting::Known(name), Some(value)) => settings.push((*name, value)),
            (setting, _) => {
                setting_errors.push((setting.clone(), SoapErrorCode::SettingIsNotAvailable))
            }
        }
    }
    UserResponse {
        error: SoapErrorCode::NoError,
        message: Cow::Borrowed(""),
        redirect_target: None,
        settings,
        setting_errors,
    }
}

fn user_setting<'x>(
    server: &'x Server,
    version: &ServerVersionInfo,
    endpoints: &Endpoints<'x>,
    mailbox: &'x Mailbox,
    data_access: bool,
    oab_url: Option<&'x str>,
    name: UserSettingName,
) -> Option<UserSettingValue<'x>> {
    let text = |value: &'x str| Some(UserSettingValue::String(Cow::Borrowed(value)));
    let owned = |value: String| Some(UserSettingValue::String(Cow::Owned(value)));
    match name {
        UserSettingName::UserDisplayName => text(&mailbox.display_name),
        UserSettingName::AutoDiscoverSMTPAddress => text(&mailbox.smtp),
        UserSettingName::UserDN => identity::legacy_dn(mailbox.account_id, &mailbox.primary)
            .map(|dn| UserSettingValue::String(Cow::Owned(dn.as_str().to_string()))),
        UserSettingName::UserDeploymentId => {
            let mut guid = Vec::with_capacity(36);
            identity::deployment_guid(&server.core.network.server_name).write_text(
                &mut guid,
                HexCase::Lower,
                Braces::None,
            );
            String::from_utf8(guid).ok().and_then(owned)
        }
        UserSettingName::UserMSOnline | UserSettingName::CrossOrganizationSharingEnabled => {
            text("False")
        }
        UserSettingName::CasVersion | UserSettingName::MailboxVersion => {
            owned(cas_version(version))
        }
        UserSettingName::EwsSupportedSchemas => owned(supported_schemas(version.version)),
        UserSettingName::ExternalEwsUrl | UserSettingName::InternalEwsUrl if data_access => {
            owned(endpoints.ews())
        }
        UserSettingName::ExternalEwsVersion if data_access => owned(cas_version(version)),
        UserSettingName::InternalOABUrl | UserSettingName::ExternalOABUrl => oab_url.and_then(text),
        UserSettingName::ExternalMailboxServer if data_access => text(endpoints.host),
        UserSettingName::ExternalMailboxServerRequiresSSL if data_access => text("True"),
        UserSettingName::ExternalMailboxServerAuthenticationMethods if data_access => text("Basic"),
        UserSettingName::InternalImap4Connections | UserSettingName::ExternalImap4Connections => {
            connections(server, ServiceProtocol::Imap, 993)
        }
        UserSettingName::InternalPop3Connections | UserSettingName::ExternalPop3Connections => {
            connections(server, ServiceProtocol::Pop3, 995)
        }
        UserSettingName::InternalSmtpConnections | UserSettingName::ExternalSmtpConnections => {
            connections(server, ServiceProtocol::Smtp, 465)
        }
        _ => None,
    }
}

fn connections(
    server: &Server,
    protocol: ServiceProtocol,
    port: u16,
) -> Option<UserSettingValue<'_>> {
    server
        .core
        .network
        .info
        .services
        .get(&protocol)
        .map(|service| {
            UserSettingValue::ProtocolConnections(vec![ProtocolConnection {
                hostname: Cow::Borrowed(
                    service
                        .hostname
                        .as_deref()
                        .unwrap_or(&server.core.network.server_name),
                ),
                port,
                encryption: Some(Encryption::Ssl),
            }])
        })
}

fn domain_response<'x>(
    server: &'x Server,
    version: &ServerVersionInfo,
    local: bool,
    data_access: bool,
    requested: &[RequestedSetting<'x>],
) -> DomainResponse<'x> {
    if !local {
        let code = SoapErrorCode::InvalidDomain;
        return DomainResponse {
            error: code,
            message: Cow::Borrowed(code.default_message()),
            settings: Vec::new(),
            setting_errors: Vec::new(),
            redirect_target: None,
        };
    }
    let mut settings = Vec::with_capacity(requested.len());
    let mut setting_errors = Vec::new();
    for setting in requested {
        let value = match setting {
            RequestedSetting::Known(UserSettingName::ExternalEwsUrl) if data_access => Some((
                DomainSettingName::ExternalEwsUrl,
                Endpoints::new(server).ews(),
            )),
            RequestedSetting::Known(UserSettingName::ExternalEwsVersion) if data_access => {
                Some((DomainSettingName::ExternalEwsVersion, cas_version(version)))
            }
            _ => None,
        };
        match value {
            Some((name, value)) => settings.push((name, Cow::Owned(value))),
            None => setting_errors.push((setting.clone(), SoapErrorCode::SettingIsNotAvailable)),
        }
    }
    DomainResponse {
        error: SoapErrorCode::NoError,
        message: Cow::Borrowed(""),
        settings,
        setting_errors,
        redirect_target: None,
    }
}

pub(super) fn cas_version(version: &ServerVersionInfo) -> String {
    format!(
        "{}.{:02}.{:04}.{:03}",
        version.major, version.minor, version.major_build, version.minor_build
    )
}

pub(super) fn supported_schemas(max: ExchangeVersion) -> String {
    let mut schemas = String::with_capacity(160);
    for version in ExchangeVersion::ALL
        .iter()
        .filter(|version| **version <= max && !is_internal_version(**version))
    {
        if !schemas.is_empty() {
            schemas.push_str(", ");
        }
        schemas.push_str(version.as_str());
    }
    schemas
}

fn is_internal_version(version: ExchangeVersion) -> bool {
    matches!(
        version,
        ExchangeVersion::Exchange2009
            | ExchangeVersion::Exchange2012
            | ExchangeVersion::Exchange2015
    )
}
