/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

pub mod emsmdb;
pub mod http;
pub mod ids;
pub mod nspi;
pub mod session;
pub mod text;

use common::{Server, auth::AccessToken};
use emsmdb::{EmsmdbRequest, WaitOutcome};
use exchange_proto::mapi::{Endpoint, RequestType, ResponseCode};
use http::{EnvelopeError, Expiration, endpoint_from_path, parse_envelope};
use http_proto::{HttpRequest, HttpResponse, HttpSessionData, request::fetch_body};
use hyper::Method;
use nspi::NspiRequestHandler;

pub trait MapiHandler: Sync + Send {
    fn handle_mapi(
        &self,
        request: HttpRequest,
        access_token: AccessToken,
        session: &HttpSessionData,
    ) -> impl Future<Output = trc::Result<HttpResponse>> + Send;
}

impl MapiHandler for Server {
    async fn handle_mapi(
        &self,
        mut request: HttpRequest,
        access_token: AccessToken,
        session: &HttpSessionData,
    ) -> trc::Result<HttpResponse> {
        if request.method() != Method::POST {
            return Ok(EnvelopeError::new(ResponseCode::InvalidVerb).into_response());
        }
        let Some(endpoint) = endpoint_from_path(request.uri().path()) else {
            return Ok(EnvelopeError::new(ResponseCode::InvalidPath).into_response());
        };
        let envelope = match parse_envelope(&request, endpoint) {
            Ok(envelope) => envelope,
            Err(err) => return Ok(err.into_response()),
        };
        let Some(body) = fetch_body(
            &mut request,
            self.core.exchange.max_request_size,
            session.session_id,
        )
        .await
        else {
            return Ok(envelope.error(ResponseCode::TooLarge));
        };
        let reply = match endpoint {
            Endpoint::Emsmdb => {
                let request = EmsmdbRequest {
                    server: self,
                    access_token: &access_token,
                    instance: &session.instance,
                    envelope: &envelope,
                    body: &body,
                };
                match envelope.request_type {
                    RequestType::Connect => request.connect().await,
                    RequestType::Execute => request.execute().await,
                    RequestType::Disconnect => request.disconnect().await,
                    RequestType::NotificationWait => match request.notification_wait().await {
                        Ok(WaitOutcome::Wait(wait)) => {
                            return Ok(envelope.streamed_reply(
                                Expiration::Session,
                                wait.cookies(),
                                wait.run(),
                            ));
                        }
                        Ok(WaitOutcome::Reply(reply)) => Ok(reply),
                        Err(err) => Err(err),
                    },
                    RequestType::Ping => request.ping().await,
                    _ => return Ok(envelope.error(ResponseCode::InvalidRequestType)),
                }
            }
            Endpoint::Nspi => {
                NspiRequestHandler {
                    server: self,
                    access_token: &access_token,
                    envelope: &envelope,
                    body: &body,
                }
                .handle()
                .await
            }
        };
        let reply = match reply {
            Ok(reply) => reply,
            Err(err) => {
                trc::error!(err.details("MAPI request failed"));
                return Ok(envelope.error(ResponseCode::UnknownFailure));
            }
        };
        Ok(envelope.reply(reply))
    }
}
