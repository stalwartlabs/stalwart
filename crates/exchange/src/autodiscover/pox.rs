/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{Endpoints, Mailbox, MailboxAddress, has_data_access, resolve_mailbox};
use crate::{
    cache::ExchangeCacheFetch,
    identity,
    mapi::{emsmdb::access::LogonAccess, http::endpoint_path},
    oab::advertised_url,
};
use common::{Server, auth::AccessToken};
use exchange_proto::{
    autodiscover::{
        AdAccount, AdLimits, AdUser, AltMailboxKind, AltMailboxTarget, AlternativeMailbox,
        AuthPackage, ClientCanHandle, Encryption, ExchangeProtocol, MailProtocol, MailboxAccess,
        MapiHttpCapability, MobileServer, MobileSyncAction, MobileSyncResponse, PoxErrorCode,
        PoxRequest, RpcBlocks, UrlPair, XML_CONTENT_TYPE, parse_pox_request,
        user_agent_is_mapi_http_outlook, write_mobilesync_response, write_outlook_response,
        write_pox_error,
    },
    common::{Braces, HexCase, time::UtcSeconds},
    mapi::http::Endpoint,
};
use http_proto::{HttpRequest, HttpResponse, HttpSessionData, request::fetch_body};
use hyper::{Method, StatusCode, header::USER_AGENT};
use registry::schema::enums::ServiceProtocol;
use smallvec::SmallVec;
use std::{borrow::Cow, num::NonZeroU32};
use store::write::now;

const MOBILESYNC_CULTURE: &str = "en:us";
const MOBILESYNC_ERROR_STATUS: u8 = 2;
const MAILBOX_ID_QUERY: &str = "/?MailboxId=";
const GUID_TEXT_LEN: usize = 36;
const X_MAPI_HTTP_CAPABILITY: &str = "x-mapihttpcapability";
const X_CLIENT_CAN_HANDLE: &str = "x-clientcanhandle";
const MAX_ALTERNATIVE_MAILBOXES: usize = 16;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum OutlookClient {
    MapiHttp(ExHttp),
    Generic,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ExHttp {
    Requested,
    NotRequested,
}

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord)]
struct MappedMailbox {
    display_name: Box<str>,
    smtp: String,
}

impl OutlookClient {
    fn detect(request: &HttpRequest) -> Self {
        let headers = request.headers();
        let outlook = headers
            .get(USER_AGENT)
            .is_some_and(|ua| user_agent_is_mapi_http_outlook(ua.as_bytes()));
        if !outlook
            && headers
                .get(X_MAPI_HTTP_CAPABILITY)
                .and_then(|value| MapiHttpCapability::parse(Some(value.as_bytes())))
                .is_none()
        {
            return OutlookClient::Generic;
        }
        let ex_http_info = || {
            ClientCanHandle::parse(
                headers
                    .get(X_CLIENT_CAN_HANDLE)
                    .map(|value| value.as_bytes()),
            )
            .ex_http_info
        };
        OutlookClient::MapiHttp(if outlook || ex_http_info() {
            ExHttp::Requested
        } else {
            ExHttp::NotRequested
        })
    }
}

pub trait PoxAutodiscover: Sync + Send {
    fn handle_pox_autodiscover(
        &self,
        request: HttpRequest,
        access_token: Option<AccessToken>,
        session: &HttpSessionData,
    ) -> impl Future<Output = trc::Result<HttpResponse>> + Send;
}

impl PoxAutodiscover for Server {
    async fn handle_pox_autodiscover(
        &self,
        mut request: HttpRequest,
        access_token: Option<AccessToken>,
        session: &HttpSessionData,
    ) -> trc::Result<HttpResponse> {
        let access_token = access_token.ok_or_else(|| {
            trc::AuthEvent::Failed
                .into_err()
                .details("Autodiscover requires authentication.")
        })?;
        let limits = AdLimits::DEFAULT;
        let max_body = usize::try_from(limits.max_pox_body).unwrap_or(usize::MAX);
        let error_id = u32::try_from(session.session_id & u64::from(u32::MAX)).unwrap_or_default();
        if request.method() == Method::GET {
            return Ok(pox_error(PoxErrorCode::InvalidRequest600, error_id));
        }
        let client = OutlookClient::detect(&request);
        let Some(body) = fetch_body(&mut request, max_body, session.session_id).await else {
            return Ok(pox_error(PoxErrorCode::InvalidRequest600, error_id));
        };
        let data_access = has_data_access(&access_token);

        match parse_pox_request(&body, &limits) {
            Ok(PoxRequest::Outlook { email, legacy_dn }) => {
                let address = match (&legacy_dn, &email) {
                    (Some(dn), _) => MailboxAddress::LegacyDn(dn),
                    (None, Some(email)) => MailboxAddress::Smtp(email),
                    (None, None) => MailboxAddress::Own,
                };
                match resolve_mailbox(self, &access_token, address).await? {
                    Some(mailbox) => {
                        let mailbox_id = if matches!(client, OutlookClient::MapiHttp(_))
                            && data_access
                            && LogonAccess::of(&access_token, mailbox.account_id).is_some()
                        {
                            mailbox_id(self, &mailbox).await?
                        } else {
                            None
                        };
                        let mapped =
                            if data_access && access_token.is_account_id(mailbox.account_id) {
                                mapped_mailboxes(self, &access_token).await?
                            } else {
                                Vec::new()
                            };
                        let oab_url = if data_access {
                            advertised_url(self, &access_token).await
                        } else {
                            None
                        };
                        Ok(xml_response(outlook_response(
                            self,
                            &mailbox,
                            data_access,
                            client,
                            mailbox_id.as_deref(),
                            &mapped,
                            oab_url.as_deref(),
                        )))
                    }
                    None => Ok(pox_error(PoxErrorCode::NotFound500, error_id)),
                }
            }
            Ok(PoxRequest::MobileSync { email }) => {
                mobilesync(
                    self,
                    &access_token,
                    data_access,
                    MailboxAddress::Smtp(&email),
                )
                .await
            }
            Ok(PoxRequest::Empty) => {
                mobilesync(self, &access_token, data_access, MailboxAddress::Own).await
            }
            Ok(PoxRequest::UnknownSchema) => {
                Ok(pox_error(PoxErrorCode::ProviderUnavailable601, error_id))
            }
            Err(err) => Ok(pox_error(err.code(), error_id)),
        }
    }
}

async fn mobilesync(
    server: &Server,
    access_token: &AccessToken,
    data_access: bool,
    address: MailboxAddress<'_>,
) -> trc::Result<HttpResponse> {
    let mailbox = if data_access {
        resolve_mailbox(server, access_token, address).await?
    } else {
        None
    };
    let Some(mailbox) = mailbox else {
        let code = PoxErrorCode::NotFound500;
        let response = MobileSyncResponse {
            culture: MOBILESYNC_CULTURE,
            display_name: None,
            email: Cow::Borrowed(match address {
                MailboxAddress::Smtp(email) => email,
                MailboxAddress::LegacyDn(_) | MailboxAddress::Own => "",
            }),
            action: MobileSyncAction::Error {
                status: MOBILESYNC_ERROR_STATUS,
                message: Cow::Borrowed(code.default_message()),
                debug_data: Cow::Borrowed(""),
                error_code: u32::from(code.code()),
            },
        };
        let mut out = Vec::with_capacity(512);
        write_mobilesync_response(&mut out, &response);
        return Ok(xml_response(out));
    };
    let url = Endpoints::new(server).eas();
    let response = MobileSyncResponse {
        culture: MOBILESYNC_CULTURE,
        display_name: Some(Cow::Borrowed(&mailbox.display_name)),
        email: Cow::Borrowed(&mailbox.smtp),
        action: MobileSyncAction::Settings {
            server: MobileServer::MobileSync {
                url: Cow::Owned(url),
            },
            more_servers: SmallVec::new(),
        },
    };
    let mut out = Vec::with_capacity(1024);
    write_mobilesync_response(&mut out, &response);
    Ok(xml_response(out))
}

async fn mailbox_id(server: &Server, mailbox: &Mailbox) -> trc::Result<Option<String>> {
    let cache = server.get_cached_exchange(mailbox.account_id).await?;
    let domain = mailbox
        .primary
        .rsplit_once('@')
        .map_or_else(|| Endpoints::new(server).host, |(_, domain)| domain);
    let mut mailbox_id = Vec::with_capacity(GUID_TEXT_LEN + 1 + domain.len());
    identity::mailbox_guid(cache.store_instance, mailbox.account_id).write_text(
        &mut mailbox_id,
        HexCase::Lower,
        Braces::None,
    );
    mailbox_id.push(b'@');
    mailbox_id.extend_from_slice(domain.as_bytes());
    Ok(String::from_utf8(mailbox_id).ok())
}

async fn mapped_mailboxes(
    server: &Server,
    access_token: &AccessToken,
) -> trc::Result<Vec<MappedMailbox>> {
    let member_ids = access_token.member_ids();
    let mut mapped = Vec::with_capacity(member_ids.size_hint().0.saturating_sub(1));
    for account_id in member_ids.filter(|&account_id| !access_token.is_account_id(account_id)) {
        let Some(account) = server.try_account(account_id).await? else {
            continue;
        };
        let Some(smtp) = identity::primary_address(server, &account).await? else {
            continue;
        };
        mapped.push(MappedMailbox {
            display_name: account
                .description
                .clone()
                .unwrap_or_else(|| account.name.clone()),
            smtp,
        });
    }
    mapped.sort_unstable();
    mapped.truncate(MAX_ALTERNATIVE_MAILBOXES);
    Ok(mapped)
}

fn mapi_url(endpoints: &Endpoints<'_>, endpoint: Endpoint, mailbox_id: &str) -> String {
    let path = endpoint_path(endpoint);
    let mut url = String::with_capacity(
        endpoints.base.len() + path.len() + MAILBOX_ID_QUERY.len() + mailbox_id.len(),
    );
    url.push_str(endpoints.base);
    url.push_str(path);
    url.push_str(MAILBOX_ID_QUERY);
    url.push_str(mailbox_id);
    url
}

fn url_pair(url: &str) -> UrlPair<'_> {
    UrlPair::Both {
        internal: Cow::Borrowed(url),
        external: Cow::Borrowed(url),
    }
}

fn exchange_protocol<'x>(
    host: &'x str,
    ews_url: &'x str,
    oab_url: Option<&'x str>,
    auth_package: AuthPackage,
    server_exclusive_connect: bool,
) -> ExchangeProtocol<'x> {
    ExchangeProtocol {
        server: Cow::Borrowed(host),
        server_dn: None,
        server_version: None,
        mdb_dn: None,
        ssl: true,
        auth_package,
        as_url: Cow::Borrowed(ews_url),
        ews_url: Cow::Borrowed(ews_url),
        oab_url: oab_url.map(Cow::Borrowed),
        oof_url: Some(Cow::Borrowed(ews_url)),
        server_exclusive_connect,
        public_folder_server: None,
        cert_principal_name: None,
    }
}

fn outlook_response(
    server: &Server,
    mailbox: &Mailbox,
    data_access: bool,
    client: OutlookClient,
    mapi_mailbox_id: Option<&str>,
    mapped: &[MappedMailbox],
    oab_url: Option<&str>,
) -> Vec<u8> {
    let endpoints = Endpoints::new(server);
    let legacy_dn = identity::legacy_dn(mailbox.account_id, &mailbox.primary);
    let ews_url = data_access.then(|| endpoints.ews());
    let ews_url = ews_url.as_deref();
    let host = endpoints.host;
    let mapi_urls = mapi_mailbox_id.map(|mailbox_id| {
        (
            mapi_url(&endpoints, Endpoint::Emsmdb, mailbox_id),
            mapi_url(&endpoints, Endpoint::Nspi, mailbox_id),
        )
    });
    let mailbox_access = match (&mapi_urls, client) {
        (Some((mail_store, address_book)), _) => Some(MailboxAccess::MapiHttp {
            version: NonZeroU32::MIN,
            mail_store: url_pair(mail_store),
            address_book: url_pair(address_book),
        }),
        (None, OutlookClient::Generic) => ews_url.map(|ews_url| {
            MailboxAccess::Rpc(RpcBlocks::Both {
                exch: exchange_protocol(host, ews_url, oab_url, AuthPackage::Anonymous, false),
                expr: exchange_protocol(host, ews_url, oab_url, AuthPackage::Basic, true),
            })
        }),
        (None, OutlookClient::MapiHttp(_)) => None,
    };
    let ex_http = match client {
        OutlookClient::MapiHttp(ExHttp::Requested) => ews_url
            .map(|ews_url| exchange_protocol(host, ews_url, oab_url, AuthPackage::Basic, true)),
        OutlookClient::MapiHttp(ExHttp::NotRequested) | OutlookClient::Generic => None,
    };
    let services = &server.core.network.info.services;
    let mail_protocol = |protocol: ServiceProtocol, port: u16| {
        services.get(&protocol).map(|service| MailProtocol {
            server: Cow::Borrowed(
                service
                    .hostname
                    .as_deref()
                    .unwrap_or(&server.core.network.server_name),
            ),
            port,
            login_name: Cow::Borrowed(mailbox.smtp.as_str()),
            ssl: true,
            encryption: Some(Encryption::Ssl),
            spa: false,
            auth_required: true,
        })
    };
    let response = exchange_proto::autodiscover::OutlookResponse {
        user: AdUser {
            display_name: Cow::Borrowed(&mailbox.display_name),
            legacy_dn: legacy_dn
                .as_ref()
                .map_or(Cow::Borrowed(""), |dn| Cow::Borrowed(dn.as_str())),
            smtp_address: Cow::Borrowed(&mailbox.smtp),
            deployment_id: identity::deployment_guid(&server.core.network.server_name),
            default_ab_view_contacts: false,
        },
        account: AdAccount {
            microsoft_online: false,
            mailbox: mailbox_access,
            ex_http,
            web: None,
            imap: mail_protocol(ServiceProtocol::Imap, 993),
            pop3: mail_protocol(ServiceProtocol::Pop3, 995),
            smtp: mail_protocol(ServiceProtocol::Smtp, 465),
            public_folder_smtp: None,
            alternative_mailboxes: mapped
                .iter()
                .map(|mailbox| AlternativeMailbox {
                    kind: AltMailboxKind::Delegate,
                    display_name: Cow::Borrowed(&mailbox.display_name),
                    target: AltMailboxTarget::Smtp(Cow::Borrowed(&mailbox.smtp)),
                    owner_smtp_address: Some(Cow::Borrowed(&mailbox.smtp)),
                })
                .collect(),
        },
    };
    let mut out = Vec::with_capacity(2048);
    write_outlook_response(&mut out, &response);
    out
}

fn pox_error(code: PoxErrorCode, id: u32) -> HttpResponse {
    let mut out = Vec::with_capacity(512);
    let time = UtcSeconds(i64::try_from(now()).unwrap_or_default());
    write_pox_error(&mut out, code, code.default_message(), "", time, id);
    xml_response(out)
}

pub(crate) fn xml_response(body: Vec<u8>) -> HttpResponse {
    HttpResponse::new(StatusCode::OK)
        .with_content_type(XML_CONTENT_TYPE)
        .with_binary_body(body)
        .with_no_store()
}
