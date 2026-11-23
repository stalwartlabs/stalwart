/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    autodiscover::{json::handle_json_autodiscover, pox::PoxAutodiscover, soap::SoapAutodiscover},
    eas::EasHandler,
    ews::EwsHandler,
    mapi::MapiHandler,
    oab::OabHandler,
};
use common::{
    Server,
    auth::{AccessToken, oauth::scope::OAuthScopes},
    config::exchange::ExchangeEndpoint,
};
use http_proto::{HttpRequest, HttpResponse, HttpSessionData};
use hyper::Method;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AutodiscoverDocument {
    Pox,
    Soap,
    Json,
}

impl AutodiscoverDocument {
    pub fn parse(name: &str) -> Option<Self> {
        hashify::map_ignore_case!(name.as_bytes(), AutodiscoverDocument,
            "autodiscover.xml" => AutodiscoverDocument::Pox,
            "autodiscover.svc" => AutodiscoverDocument::Soap,
            "autodiscover.json" => AutodiscoverDocument::Json,
        )
        .copied()
    }

    pub fn is_routed(self, method: &Method) -> bool {
        match self {
            AutodiscoverDocument::Json => true,
            AutodiscoverDocument::Pox => method == Method::POST || method == Method::GET,
            AutodiscoverDocument::Soap => method == Method::POST,
        }
    }
}

pub const AUTODISCOVER_CAPABILITY_HEADERS: &[(&str, &str)] = &[("X-SOAP-Enabled", "True")];

pub trait ExchangeRequestHandler: Sync + Send {
    fn handle_exchange_request(
        &self,
        request: HttpRequest,
        endpoint: ExchangeEndpoint,
        access_token: AccessToken,
        session: &HttpSessionData,
    ) -> impl Future<Output = trc::Result<HttpResponse>> + Send;

    fn handle_exchange_autodiscover(
        &self,
        request: HttpRequest,
        document: AutodiscoverDocument,
        access_token: Option<AccessToken>,
        session: &HttpSessionData,
    ) -> impl Future<Output = trc::Result<HttpResponse>> + Send;
}

impl ExchangeRequestHandler for Server {
    async fn handle_exchange_request(
        &self,
        request: HttpRequest,
        endpoint: ExchangeEndpoint,
        access_token: AccessToken,
        session: &HttpSessionData,
    ) -> trc::Result<HttpResponse> {
        let access_token = access_token.assert_allows_oauth_scopes(OAuthScopes::INTEROPERABLE)?;
        match endpoint {
            ExchangeEndpoint::Ews => {
                self.handle_ews_request(request, access_token, session)
                    .await
            }
            ExchangeEndpoint::Mapi => {
                Box::pin(self.handle_mapi(request, access_token, session)).await
            }
            ExchangeEndpoint::ActiveSync => {
                self.handle_eas_request(request, access_token, session)
                    .await
            }
            ExchangeEndpoint::OfflineAddressBook => self.handle_oab(request, access_token).await,
        }
    }

    async fn handle_exchange_autodiscover(
        &self,
        request: HttpRequest,
        document: AutodiscoverDocument,
        access_token: Option<AccessToken>,
        session: &HttpSessionData,
    ) -> trc::Result<HttpResponse> {
        match document {
            AutodiscoverDocument::Pox => {
                self.handle_pox_autodiscover(request, access_token, session)
                    .await
            }
            AutodiscoverDocument::Soap => {
                self.handle_soap_autodiscover(request, access_token, session)
                    .await
            }
            AutodiscoverDocument::Json => Ok(handle_json_autodiscover(
                self,
                &request,
                access_token.as_ref(),
            )),
        }
    }
}

#[cfg(all(test, stalwart_tests))]
#[rustfmt::skip]
#[path = "../../../../stalwart-tests/unit/exchange/src/request/tests.rs"]
mod tests;
