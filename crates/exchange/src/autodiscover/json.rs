/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{Endpoints, has_data_access};
use common::{Server, auth::AccessToken};
use exchange_proto::autodiscover::{
    JSON_CONTENT_TYPE, V2ErrorCode, V2Protocol, parse_v2_request, write_v2_error, write_v2_success,
};
use http_proto::{HttpRequest, HttpResponse};
use hyper::StatusCode;

const POX_PATH: &str = "/autodiscover/autodiscover.xml";
const MISSING_EMAIL: &str = "A valid email address is required.";
const MISSING_PROTOCOL: &str = "A protocol value is required.";
const INVALID_PROTOCOL: &str = "The given protocol value is invalid. Supported values are 'ActiveSync', 'AutodiscoverV1', 'Ews'.";

pub(crate) fn handle_json_autodiscover(
    server: &Server,
    request: &HttpRequest,
    access_token: Option<&AccessToken>,
) -> HttpResponse {
    let mut out = Vec::with_capacity(160);
    let data_access = access_token.is_none_or(has_data_access);
    let status = json_response(
        &Endpoints::new(server),
        data_access,
        request.uri().path(),
        request.uri().query(),
        &mut out,
    );
    HttpResponse::new(status)
        .with_content_type(JSON_CONTENT_TYPE)
        .with_binary_body(out)
        .with_no_store()
}

pub(crate) fn json_response(
    endpoints: &Endpoints<'_>,
    data_access: bool,
    path: &str,
    query: Option<&str>,
    out: &mut Vec<u8>,
) -> StatusCode {
    let path_tail = path
        .trim_start_matches('/')
        .splitn(3, '/')
        .nth(2)
        .unwrap_or_default();
    let v2 = parse_v2_request(path_tail, query);
    let has_domain = v2
        .email
        .as_deref()
        .and_then(|email| email.rsplit_once('@'))
        .is_some_and(|(_, domain)| !domain.is_empty());
    let result = match v2.protocol {
        _ if !has_domain => Err((V2ErrorCode::MandatoryParameterMissing, MISSING_EMAIL)),
        Ok(protocol @ V2Protocol::ActiveSync) if data_access => Ok((protocol, endpoints.eas())),
        Ok(protocol @ V2Protocol::Ews) if data_access => Ok((protocol, endpoints.ews())),
        Ok(protocol @ V2Protocol::AutodiscoverV1) => Ok((protocol, endpoints.url(POX_PATH))),
        Ok(
            V2Protocol::ActiveSync | V2Protocol::Ews | V2Protocol::Rest | V2Protocol::CloudOnly(_),
        )
        | Err(V2ErrorCode::InvalidProtocol) => {
            Err((V2ErrorCode::InvalidProtocol, INVALID_PROTOCOL))
        }
        Err(code) => Err((code, MISSING_PROTOCOL)),
    };
    match result {
        Ok((protocol, url)) => {
            write_v2_success(out, protocol, &url);
            StatusCode::OK
        }
        Err((code, message)) => {
            write_v2_error(out, code, message);
            StatusCode::BAD_REQUEST
        }
    }
}

#[cfg(all(test, stalwart_tests))]
#[rustfmt::skip]
#[path = "../../../../../stalwart-tests/unit/exchange/src/autodiscover/json/tests.rs"]
mod tests;
